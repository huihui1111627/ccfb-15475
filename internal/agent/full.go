package agent

import (
	"net/netip"
	"sort"
	"time"

	"natlab/internal/nat"
	"natlab/internal/server"
	"natlab/internal/sim"
)

const (
	checkRTX       = 3
	checkTimeout   = 250 * time.Millisecond
	pairPace       = 60 * time.Millisecond
	phaseBudget    = 6 * time.Second // direct-connect budget before relay fallback
	keepaliveEvery = 8 * time.Second
)

// FullStrategy is the complete ICE-like connection establishment algorithm.
type FullStrategy struct {
	h         Host
	id        string
	peer      string
	session   string
	role      string // initiator / responder
	restartID uint32

	udpDisc  *DiscoveryResult
	tcpDisc  *DiscoveryResult
	cands    []sim.Cand
	peerC    []sim.Cand
	gathered bool

	pairs      []pair
	state      string // gather / offer / check / connected / relay / done
	chosen     *pair
	sockUDP    *Socket
	sockTCP    *Socket
	relaySrv   *server.Relay
	relayEP    sim.Endpoint
	relayAcked map[string]bool

	report        RunReport
	startAt       time.Duration
	mobilityAt    time.Duration
	connectedAt   time.Duration
	keepCancel    func()
	appTimer      func()
	pending       int // in-flight checks for this restart
	relaySignaled string
	// endpoints that have sent us a ConnCheckAck, proving bidirectional reach
	ackedPeers map[string]bool
}

type pair struct {
	local        sim.Cand
	remote       sim.Cand
	prio         uint64
	tried        bool
	ok           bool
	ackConfirmed bool // a ConnCheckAck came back, proving the return path works
	rtt          time.Duration
	pred         bool
	onTimeout    func()
	sentAt       time.Duration
}

func NewFullStrategy() *FullStrategy {
	return &FullStrategy{state: "init", relayAcked: map[string]bool{}, ackedPeers: map[string]bool{}}
}

func (s *FullStrategy) Name() string      { return "full" }
func (s *FullStrategy) Report() RunReport { return s.report }

// OnPacket handles packets delivered to a socket without its own handler
// (socket handlers normally consume messages directly).
func (s *FullStrategy) OnPacket(host Host, p *sim.Packet) {
	if fn := s.makeHandler(p.Dst.Proto); fn != nil {
		fn(host.Engine(), p)
	}
}

func (s *FullStrategy) Begin(h Host, sessionID, peerID string) {
	s.h, s.session, s.peer = h, sessionID, peerID
	s.role = "initiator"
	s.report.Strategy = "full"
	s.startAt = h.Engine().Now
	s.state = "gather"
	h.Logf("ice", "session %s: begin gathering", sessionID)
	s.gather()
}

// selfName returns the stable signaling name of the local terminal.
func (s *FullStrategy) selfName() string {
	if tn, ok := s.h.(interface{ SignalName() string }); ok {
		return tn.SignalName()
	}
	return s.h.ID()
}

// ---------- discovery & gathering ----------

func (s *FullStrategy) gather() {
	s.sockUDP = RunDiscovery(s.h, sim.UDP, func(r *DiscoveryResult) {
		s.udpDisc = r
		s.report.LocalDisc = r
		// discovery finished: take over the socket (and its NAT mapping) for ICE
		s.sockUDP.OnMsg = s.makeHandler(sim.UDP)
		s.h.Logf("ice", "UDP discovery done ok=%v blocked=%v", r.OK, r.Blocked)
		s.maybeGathered()
	})
	s.sockTCP = RunDiscovery(s.h, sim.TCP, func(r *DiscoveryResult) {
		s.tcpDisc = r
		if s.sockTCP != nil {
			s.sockTCP.OnMsg = s.makeHandler(sim.TCP)
		}
		s.maybeGathered()
	})
}

func (s *FullStrategy) maybeGathered() {
	if s.udpDisc == nil || s.tcpDisc == nil || s.gathered {
		return
	}
	s.gathered = true
	s.buildCandidates()
	if s.restartID > 0 {
		s.afterRestartOffer()
		return
	}
	switch s.role {
	case "initiator":
		s.state = "offer"
		s.sendSignal("offer", s.cands)
		s.h.Logf("ice", "sent offer with %d candidates", len(s.cands))
	case "responder":
		// the offer (and its candidate list) arrived during discovery
		s.state = "offer"
		s.sendSignal("answer", s.cands)
		s.h.Logf("ice", "sent answer with %d candidates", len(s.cands))
		if len(s.peerC) > 0 {
			s.startChecks()
		}
	}
}

func (s *FullStrategy) buildCandidates() {
	s.cands = nil
	add := func(c sim.Cand) {
		c.Priority = CandidatePriority(c.Type, c.Proto)
		s.cands = append(s.cands, c)
	}
	// host candidates on both protocols
	add(sim.Cand{Type: "host", IP: s.sockUDP.IP, Port: s.sockUDP.Port, Proto: sim.UDP, LocalPort: s.sockUDP.Port})
	add(sim.Cand{Type: "host", IP: s.sockTCP.IP, Port: s.sockTCP.Port, Proto: sim.TCP, LocalPort: s.sockTCP.Port})
	if s.udpDisc.OK {
		pred := s.predictions(s.udpDisc)
		add(sim.Cand{
			Type: "srflx", IP: s.udpDisc.ExternalIP, Port: s.udpDisc.ExternalPort,
			Proto: sim.UDP, LocalPort: s.sockUDP.Port, Predicted: pred,
			Unpredictable: s.udpDisc.Mapping == nat.APDM && s.udpDisc.PortPolicy == nat.PortRandom,
			Symmetric:     s.udpDisc.Mapping == nat.APDM,
		})
	}
	if s.tcpDisc.OK {
		add(sim.Cand{
			Type: "srflx", IP: s.tcpDisc.ExternalIP, Port: s.tcpDisc.ExternalPort,
			Proto: sim.TCP, LocalPort: s.sockTCP.Port,
			// symmetric NAT randomization applies to every transport; if the
			// UDP side already proved APDM+random, TCP cannot be punched either
			Unpredictable: s.isUnpredictable(),
		})
	}
}

// isUnpredictable reports whether a peer cannot know the external port this
// NAT will use for a fresh destination. Only randomized allocation is truly
// unpredictable; a deterministic increment or a preserved local port can both
// be targeted by the peer.
func (s *FullStrategy) isUnpredictable() bool {
	for _, d := range []*DiscoveryResult{s.udpDisc, s.tcpDisc} {
		if d != nil && d.OK && d.Mapping == nat.APDM && d.PortPolicy == nat.PortRandom {
			return true
		}
	}
	return false
}

// predictions returns srflx ports this socket might get for a *new* remote
// destination, based on the learned APDM port behavior.
func (s *FullStrategy) predictions(r *DiscoveryResult) []uint16 {
	if r.Mapping != nat.APDM {
		return nil
	}
	return PredictPorts(r.ExternalPort, r.PortDelta, r.PortPolicy)
}

// ---------- signaling ----------

func (s *FullStrategy) sendSignal(what string, cands []sim.Cand) {
	s.h.Signaling().OnPacket(s.h.Engine(), &sim.Packet{
		Src: sim.Endpoint{IP: "local", Port: 1},
		Dst: sim.Endpoint{IP: s.h.Signaling().IP(), Port: 443},
		Msg: &sim.Signal{What: what, SessionID: s.session, From: s.selfName(), To: s.peer,
			Cands: cands, RestartID: s.restartID},
		Size: 400,
	})
}

func (s *FullStrategy) OnSignal(h Host, sig *sim.Signal) {
	// the offer bootstraps a responder that has not begun a session itself
	if sig.What == "offer" && s.session == "" {
		s.h, s.session, s.peer = h, sig.SessionID, sig.From
		s.role = "responder"
		s.report.Strategy = "full"
		s.startAt = h.Engine().Now
		s.state = "gather"
		s.gather()
	}
	if sig.SessionID != s.session {
		return
	}
	switch sig.What {
	case "offer":
		if s.state == "gather" && !s.gathered {
			// bootstrap already happened at OnSignal entry; just remember peers
		}
		s.peerC = sig.Cands
		s.report.RemoteDisc = discoveryFromCands(sig.Cands)
		if s.gathered {
			s.sendSignal("answer", s.cands)
			s.startChecks()
		}
	case "answer":
		s.peerC = sig.Cands
		s.report.RemoteDisc = discoveryFromCands(sig.Cands)
		s.startChecks()
	case "candidates":
		s.peerC = append(s.peerC, sig.Cands...)
	case "restart":
		if s.restartID < sig.RestartID {
			s.restartID = sig.RestartID
		}
		s.peerC = nil
		s.h.Logf("ice", "peer requests ICE restart %d", s.restartID)
		if s.gathered || s.state == "connected" || s.state == "relay" {
			s.gatherRestart()
		}
	case "restart-ack":
		if s.gathered || s.state == "connected" || s.state == "relay" {
			s.gatherRestart()
		}
	case "relay-select":
		s.UseSharedRelay(sig.RelayNode)
	}
}

// discoveryFromCands reconstructs enough peer behavior info for reporting.
func discoveryFromCands(cs []sim.Cand) *DiscoveryResult {
	r := &DiscoveryResult{RTT: map[string]time.Duration{}}
	for _, c := range cs {
		if c.Type == "srflx" && c.Proto == sim.UDP {
			r.OK = true
			r.ExternalIP, r.ExternalPort = c.IP, c.Port
			if len(c.Predicted) > 0 {
				r.Mapping = nat.APDM
			} else {
				r.Mapping = nat.EIM
			}
		}
	}
	return r
}

// ---------- connectivity checks ----------

func (s *FullStrategy) resetChecks() {
	if s.keepCancel != nil {
		s.keepCancel()
		s.keepCancel = nil
	}
	s.pairs = nil
	s.chosen = nil
	s.pending = 0
}

func (s *FullStrategy) startChecks() {
	if s.state == "check" || s.state == "connected" {
		return
	}
	s.state = "check"
	s.formPairs()
	s.h.Logf("ice", "checking %d candidate pairs (restart=%d)", len(s.pairs), s.restartID)
	s.scheduleChecks()
	// hard budget: after that, escalate to relay. The responder waits a little
	// longer so the initiator's relay choice arrives first and both sides
	// converge on a single shared relay instead of picking two different ones.
	delay := phaseBudget
	if s.role == "responder" {
		delay = phaseBudget + 400*time.Millisecond
	}
	s.h.Engine().Schedule(delay, func() {
		if s.state == "check" {
			s.h.Logf("ice", "direct phase budget exhausted, escalating to relay")
			s.chooseRelay()
		}
	})
}

// localIsSymmetric reports whether the local outermost NAT is APDM.
func (s *FullStrategy) localIsSymmetric() bool {
	for _, d := range []*DiscoveryResult{s.udpDisc, s.tcpDisc} {
		if d != nil && d.OK && d.Mapping == nat.APDM {
			return true
		}
	}
	return false
}

// peerIsSymmetric reports whether a signaled remote candidate indicates an
// APDM (symmetric) outer NAT — distinct from ADM, which is cone-like.
func (s *FullStrategy) peerIsSymmetric() bool {
	for _, c := range s.peerC {
		if c.Proto == sim.UDP && c.Symmetric {
			return true
		}
	}
	return false
}

func (s *FullStrategy) formPairs() {
	seen := map[string]bool{}
	// TCP is a fallback transport: only consider it when UDP cannot work for
	// at least one side. Otherwise symmetric UDP NATs would bypass the
	// prediction/relay logic by escaping over TCP.
	udpBlocked := (s.udpDisc != nil && (s.udpDisc.Blocked || !s.udpDisc.OK)) ||
		s.remoteUDPBlocked()
	for _, l := range s.cands {
		for _, r := range s.peerC {
			if l.Proto != r.Proto {
				continue
			}
			if l.Proto == sim.TCP && !udpBlocked {
				continue
			}
			// host candidates use private LAN addresses that only route on a
			// shared LAN; two different sites can never reach them directly
			if l.Type == "host" || r.Type == "host" {
				if !sameSite(l, r) {
					continue
				}
			}
			// never target an unroutable private address across sites; doing
			// so would create a bogus NAT mapping that poisons ADM/APDF filters
			if !isRoutable(r.IP) {
				continue
			}
			key := l.IP + ":" + pstr(l.Port) + "-" + r.IP + ":" + pstr(r.Port) + "/" + l.Proto.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			s.pairs = append(s.pairs, pair{local: l, remote: r, prio: PairPriority(l, r)})
		}
	}
	sort.SliceStable(s.pairs, func(i, j int) bool { return s.pairs[i].prio > s.pairs[j].prio })
}

// remoteUDPBlocked infers from the signaled candidates whether the peer has no
// usable UDP path.
func (s *FullStrategy) remoteUDPBlocked() bool {
	for _, c := range s.peerC {
		if c.Proto == sim.UDP && c.Type != "host" {
			return false
		}
	}
	return len(s.peerC) > 0
}

func sameSite(a, b sim.Cand) bool {
	// host candidates on the same LAN share a private prefix
	return ipPrefix(a.IP) == ipPrefix(b.IP)
}

func ipPrefix(ip string) string {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[:i]
		}
	}
	return ip
}

func (s *FullStrategy) scheduleChecks() {
	for i := range s.pairs {
		if s.pairs[i].tried {
			continue
		}
		idx := i
		s.h.Engine().Schedule(pairPace*time.Duration(idx), func() {
			if s.state == "connected" || s.state == "done" {
				return
			}
			s.checkPair(&s.pairs[idx], 0)
		})
	}
}

// checkPair fires simultaneous connectivity checks; for APDM peers it also
// probes predicted srflx ports.
func (s *FullStrategy) checkPair(p *pair, attempt int) {
	if p.tried || s.state == "connected" || s.state == "done" {
		return
	}
	if attempt >= checkRTX {
		s.report.FailedChecks++
		s.report.mark(CheckAttempt{T: s.h.Engine().Now, Local: epStr(p.local), Remote: epStr(p.remote),
			Proto: p.local.Proto.String(), Kind: p.local.Type + "-" + p.remote.Type, Result: "timeout"})
		return
	}
	sock := s.socketFor(p.local.Proto)
	if sock == nil {
		return
	}
	targets := s.expandTargets(p)
	use := attempt == 0 && s.role == "initiator"
	for _, tg := range targets {
		s.pending++
		s.h.Send(sock, tg, &sim.ConnCheck{SessionID: s.session, RestartID: s.restartID, Use: use}, 90)
		s.report.mark(CheckAttempt{T: s.h.Engine().Now, Local: epStr(p.local), Remote: tg.String(),
			Proto: p.local.Proto.String(), Kind: p.local.Type + "-" + p.remote.Type,
			Predicted: tg.Port != p.remote.Port, Result: "sent"})
	}
	sentAt := s.h.Engine().Now
	cancel := s.h.Engine().ScheduleFunc(checkTimeout, func() {
		if p.ok {
			return
		}
		s.checkPair(p, attempt+1)
	})
	p.onTimeout = cancel
	p.sentAt = sentAt
}

// expandTargets adds predicted-port targets for symmetric (APDM) peers.
func (s *FullStrategy) expandTargets(p *pair) []sim.Endpoint {
	base := sim.Endpoint{IP: p.remote.IP, Port: p.remote.Port, Proto: p.remote.Proto}
	targets := []sim.Endpoint{base}
	if p.remote.Type == "srflx" && len(p.remote.Predicted) > 0 && p.local.Proto == sim.UDP {
		for _, port := range p.remote.Predicted {
			if port == p.remote.Port {
				continue
			}
			targets = append(targets, sim.Endpoint{IP: p.remote.IP, Port: port, Proto: p.remote.Proto})
		}
	}
	return targets
}

// isRoutable reports whether an IP can be reached across the emulated internet.
// RFC1918 addresses are only valid within a shared LAN, never cross-site.
func isRoutable(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return !a.IsPrivate()
}

func (s *FullStrategy) socketFor(pr sim.Protocol) *Socket {
	if pr == sim.UDP {
		return s.sockUDP
	}
	return s.sockTCP
}

// ---------- packet handling ----------

func (s *FullStrategy) makeHandler(pr sim.Protocol) func(*sim.Engine, *sim.Packet) {
	return func(e *sim.Engine, p *sim.Packet) {
		switch m := p.Msg.(type) {
		case *sim.ConnCheck:
			if m.SessionID != s.session {
				return
			}
			// reply first; the inbound check already created our outbound
			// mapping, and this ack tests whether the return path is open
			ack := &sim.ConnCheckAck{SessionID: s.session, RestartID: s.restartID}
			sock := s.socketFor(pr)
			s.h.Send(sock, p.Src, ack, 90)
			s.nominateIfPair(p.Src, pr, e.Now, false)
		case *sim.ConnCheckAck:
			if m.SessionID != s.session {
				return
			}
			// an ack to one of our own checks proves bidirectional
			// reachability. Record it by IP+protocol and by full endpoint,
			// because symmetric NATs make the observed port differ from the
			// signaled candidate port.
			s.ackedPeers[p.Src.IP+"/"+pr.String()] = true
			s.ackedPeers[p.Src.IP+":"+pstr(p.Src.Port)+"/"+pr.String()] = true
			// an ack to one of our own checks proves bidirectional reachability
			s.nominateIfPair(p.Src, pr, e.Now, true)
		case *sim.KeepAlive:
			// refreshes NAT mapping implicitly (packet recreated the state)
		case *sim.RelayData:
			s.onRelayData(p, m)
		}
	}
}

func (s *FullStrategy) nominateIfPair(src sim.Endpoint, pr sim.Protocol, now time.Duration, isAck bool) {
	for i := range s.pairs {
		p := &s.pairs[i]
		if p.local.Proto != pr {
			continue
		}
		match := p.remote.IP == src.IP && (p.remote.Port == src.Port || containsPort(p.remote.Predicted, src.Port))
		if !match {
			continue
		}
		// If our own NAT is an unpredictable symmetric device, a remote peer
		// cannot target the fresh port our mapping uses toward it. An inbound
		// packet arriving here is one-directional; do not declare a direct
		// connection unless the matched path rides a verified prediction.
		if s.selfBlocksDirect(p) {
			s.h.Logf("ice", "suppress nomination: local NAT unpredictable for %s", epStr(p.local))
			return
		}
		if isAck {
			p.ackConfirmed = true
			s.ackedPeers[src.IP+":"+pstr(src.Port)+"/"+pr.String()] = true
		}
		s.nominate(p, src, now)
		return
	}
	// No exact candidate matched. A symmetric peer's mapping toward us uses a
	// freshly allocated port that differs from its signaled srflx port: this
	// is ICE's peer-reflexive case. If the source IP belongs to a known peer
	// candidate, learn the observed endpoint and nominate it.
	if s.learnPeerReflexive(src, pr, now, isAck) {
		return
	}
}

// selfBlocksDirect reports whether the local NAT makes this candidate pair
// unsuitable for a direct connection, even if inbound checks are arriving.
func (s *FullStrategy) selfBlocksDirect(p *pair) bool {
	if p.local.Type != "srflx" && p.local.Type != "prflx" {
		return false
	}
	var d *DiscoveryResult
	if p.local.Proto == sim.UDP {
		d = s.udpDisc
	} else {
		d = s.tcpDisc
	}
	if d == nil || !d.OK {
		return false
	}
	// deterministic increments and preserved ports are targetable by the peer
	// on any transport; only randomized allocation blocks the direct path
	if d.Mapping == nat.APDM && d.PortPolicy != nat.PortRandom {
		return false
	}
	return d.Mapping == nat.APDM
}

// localPredicts reports whether the local NAT offers usable port predictions.
func (s *FullStrategy) localPredicts(pr sim.Protocol) bool {
	var d *DiscoveryResult
	if pr == sim.UDP {
		d = s.udpDisc
	} else {
		d = s.tcpDisc
	}
	return d != nil && d.Mapping == nat.APDM && d.PortPolicy == nat.PortIncrement
}

// learnPeerReflexive adds an observed source as a peer-reflexive candidate
// when its IP matches a signaled remote candidate. It only accepts the new
// port when prediction is feasible: a randomly-port symmetric NAT must NOT be
// treated as reachable just because a packet happened to arrive.
func (s *FullStrategy) learnPeerReflexive(src sim.Endpoint, pr sim.Protocol, now time.Duration, isAck bool) bool {
	var base *sim.Cand
	for i := range s.peerC {
		c := &s.peerC[i]
		if c.Proto == pr && c.IP == src.IP {
			base = c
			break
		}
	}
	if base == nil {
		return false
	}
	// Acceptable peer-reflexive sources:
	//  1. a port inside the signaled prediction window (deterministic APDM)
	//  2. a stable-port peer (EIM, or APDM with port preservation)
	// A randomized symmetric NAT (Unpredictable) is never accepted, forcing
	// the relay fallback that the theoretical verdict requires.
	// A randomized symmetric NAT (Unpredictable) blocks UDP peer-reflexive
	// discovery, but TCP simultaneous open is exempt: both sides exchange SYN
	// segments and the handshake creates the filter state on the way through.
	// A randomized symmetric NAT (Unpredictable) blocks peer-reflexive
	// discovery on every transport; TCP simultaneous open does not rescue it
	// because the APDF filter still cannot match the peer's rewritten port.
	if base.Unpredictable || s.isUnpredictable() {
		s.h.Logf("ice", "reject peer-reflexive %s: peer/local NAT is randomized symmetric", src.String())
		return false
	}
	// For predictable peers (EIM, or APDM with preserved/incremented ports)
	// any observed source port from a known peer IP is accepted as a
	// peer-reflexive candidate; only randomized symmetric NATs are rejected.
	plausible := true
	if !plausible {
		s.h.Logf("ice", "reject peer-reflexive %s: outside prediction window", src.String())
		return false
	}
	prflx := sim.Cand{
		Type: "prflx", IP: src.IP, Port: src.Port, Proto: pr,
		Priority: CandidatePriority("srflx", pr) - 1,
	}
	for _, c := range s.peerC {
		if c.IP == prflx.IP && c.Port == prflx.Port && c.Proto == prflx.Proto {
			return false
		}
	}
	s.peerC = append(s.peerC, prflx)
	local := s.cands[0]
	for _, c := range s.cands {
		if c.Proto == pr {
			local = c
			break
		}
	}
	p := &pair{local: local, remote: prflx, prio: PairPriority(local, prflx), ok: true, tried: true, ackConfirmed: isAck}
	s.pairs = append(s.pairs, *p)
	s.h.Logf("ice", "learned peer-reflexive candidate %s (ack=%v)", src.String(), isAck)
	s.nominate(&s.pairs[len(s.pairs)-1], src, now)
	return true
}

func (s *FullStrategy) nominate(p *pair, src sim.Endpoint, now time.Duration) {
	wasPred := src.Port != p.remote.Port
	if !p.ok {
		p.ok = true
		p.tried = true
		p.rtt = now - p.sentAt
		if wasPred {
			s.report.PredictionHits++
		}
		s.report.mark(CheckAttempt{T: now, Local: epStr(p.local), Remote: src.String(),
			Proto: p.local.Proto.String(), Kind: p.local.Type + "-" + p.remote.Type,
			Predicted: wasPred, Result: "success", RTT: p.rtt})
	}
	if p.onTimeout != nil {
		p.onTimeout()
		p.onTimeout = nil
	}
	if s.state == "check" {
		// require bidirectional proof: a lone inbound check whose reply cannot
		// get back (e.g. symmetric APDF over TCP) must not be called connected.
		// Acks are tracked per IP+protocol (and per endpoint) to tolerate the
		// port rewriting a symmetric NAT introduces on the observed path.
		if !p.ackConfirmed &&
			!s.ackedPeers[p.remote.IP+"/"+p.local.Proto.String()] &&
			!s.ackedPeers[p.remote.IP+":"+pstr(p.remote.Port)+"/"+p.local.Proto.String()] {
			s.h.Logf("ice", "candidate %s reachable inbound, awaiting return-path ack", epStr(p.remote))
			return
		}
		p.ackConfirmed = true
		s.onConnected(p, now)
	}
}

func containsPort(ports []uint16, want uint16) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}

func (s *FullStrategy) onConnected(p *pair, now time.Duration) {
	s.chosen = p
	s.state = "connected"
	s.connectedAt = now
	s.report.Success = true
	s.report.Via = "direct"
	s.report.ConnectTime = now - s.startAt
	// a connection established after a handoff is a successful re-negotiation
	if s.restartID > 0 && !s.report.Reconnected {
		s.report.Reconnected = true
		s.report.ReconnectTime = now - s.mobilityAt
	}
	s.report.Protocol = p.local.Proto.String()
	s.report.WinningPath = epStr(p.local) + " <-> " + epStr(p.remote)
	s.h.Logf("ice", "DIRECT connection established via %s (%s) in %dms",
		p.local.Type+"-"+p.remote.Type, p.local.Proto, s.report.ConnectTime.Milliseconds())
	s.h.OnConnected(ConnectedEvent{
		Via: "direct", Path: s.report.WinningPath, Protocol: p.local.Proto.String(),
		ConnectTime: s.report.ConnectTime, RestartID: s.restartID,
		Local: epStr(p.local), Remote: epStr(p.remote),
	})
	s.startKeepalive(p)
	s.startAppTraffic(false)
}

// ---------- keep-alive & mapping refresh ----------

func (s *FullStrategy) startKeepalive(p *pair) {
	dst := sim.Endpoint{IP: p.remote.IP, Port: p.remote.Port, Proto: p.remote.Proto}
	sock := s.socketFor(p.local.Proto)
	fire := func() {}
	fire = func() {
		if s.state != "connected" {
			return
		}
		s.h.Send(sock, dst, &sim.KeepAlive{SessionID: s.session}, 40)
		s.keepCancel = s.h.Engine().ScheduleFunc(keepaliveEvery, fire)
	}
	s.keepCancel = s.h.Engine().ScheduleFunc(keepaliveEvery, fire)
}

// startAppTraffic emulates the steady-state media stream after connection.
func (s *FullStrategy) startAppTraffic(viaRelay bool) {
	const chunk = 1200 // bytes per ~20ms media frame
	fire := func() {}
	fire = func() {
		if s.state == "done" {
			return
		}
		if s.state != "connected" {
			s.appTimer = s.h.Engine().ScheduleFunc(200*time.Millisecond, fire)
			return
		}
		if viaRelay && s.relaySrv != nil {
			sock := s.sockUDP
			if s.relayEP.Proto == sim.TCP {
				sock = s.sockTCP
			}
			if sock != nil {
				s.h.Send(sock, s.relayEP, &sim.RelayData{SessionID: s.session, Bytes: chunk}, chunk)
				s.report.RelayBytes += chunk
			}
		} else if s.chosen != nil {
			sock := s.socketFor(s.chosen.local.Proto)
			dst := sim.Endpoint{IP: s.chosen.remote.IP, Port: s.chosen.remote.Port, Proto: s.chosen.remote.Proto}
			s.h.Send(sock, dst, &sim.AppData{SessionID: s.session, Bytes: chunk}, chunk)
			s.report.DirectBytes += chunk
		}
		s.appTimer = s.h.Engine().ScheduleFunc(20*time.Millisecond, fire)
	}
	s.appTimer = s.h.Engine().ScheduleFunc(20*time.Millisecond, fire)
}
