package agent

import (
	"time"

	"natlab/internal/server"
	"natlab/internal/sim"
)

// BaselineStrategy emulates a naive "simple hole punching" client:
// one UDP socket, one srflx candidate, simultaneous probes to the peer's
// reflexive address, no prediction, no TCP fallback, no keep-alive, and a
// geographically naive relay choice (first relay in the list).
type BaselineStrategy struct {
	h        Host
	id       string
	peerID   string
	session  string
	role     string
	sock     *Socket
	disc     *DiscoveryResult
	peerCand *sim.Cand
	cands    []sim.Cand
	state    string
	report   RunReport
	startAt  time.Duration
	relaySrv *server.Relay
	relayEP  sim.Endpoint
	tries    int
	appTimer func()
}

func NewBaselineStrategy() *BaselineStrategy { return &BaselineStrategy{state: "init"} }

func (b *BaselineStrategy) Name() string      { return "baseline" }
func (b *BaselineStrategy) Report() RunReport { return b.report }

func (b *BaselineStrategy) OnPacket(h Host, p *sim.Packet) { b.onPacket(h.Engine(), p) }

func (b *BaselineStrategy) Begin(h Host, sessionID, peerID string) {
	b.h, b.session, b.peerID = h, sessionID, peerID
	b.role = "initiator"
	b.report.Strategy = "baseline"
	b.startAt = h.Engine().Now
	b.state = "gather"
	b.sock = RunDiscovery(h, sim.UDP, func(r *DiscoveryResult) {
		b.disc = r
		b.report.LocalDisc = r
		c := sim.Cand{Type: "srflx", IP: r.ExternalIP, Port: r.ExternalPort, Proto: sim.UDP, LocalPort: b.sock.Port}
		c.Priority = CandidatePriority(c.Type, c.Proto)
		b.cands = []sim.Cand{c}
		b.sock.OnMsg = b.onPacket // take over the socket that holds the mapping
		b.send("offer", b.cands)
		h.Logf("ice", "baseline offer: single srflx %s", c.IP+":"+pstr(c.Port))
	})
}

func (b *BaselineStrategy) selfName() string {
	if tn, ok := b.h.(interface{ SignalName() string }); ok {
		return tn.SignalName()
	}
	return b.h.ID()
}

func (b *BaselineStrategy) send(what string, cs []sim.Cand) {
	b.h.Signaling().OnPacket(b.h.Engine(), &sim.Packet{
		Src:  sim.Endpoint{IP: "local", Port: 1},
		Dst:  sim.Endpoint{IP: b.h.Signaling().IP(), Port: 443},
		Msg:  &sim.Signal{What: what, SessionID: b.session, From: b.selfName(), To: b.peerID, Cands: cs},
		Size: 300,
	})
}

func (b *BaselineStrategy) OnSignal(h Host, sig *sim.Signal) {
	// offer bootstraps a responder with no session yet
	if sig.What == "offer" && b.session == "" {
		b.h, b.session, b.peerID = h, sig.SessionID, sig.From
		b.role = "responder"
		b.startAt = h.Engine().Now
		b.state = "gather"
		b.sock = RunDiscovery(h, sim.UDP, func(r *DiscoveryResult) {
			b.disc = r
			c := sim.Cand{Type: "srflx", IP: r.ExternalIP, Port: r.ExternalPort, Proto: sim.UDP, LocalPort: b.sock.Port}
			c.Priority = CandidatePriority(c.Type, c.Proto)
			b.cands = []sim.Cand{c}
			b.peerCand = &sig.Cands[0]
			b.report.RemoteDisc = discoveryFromCands(sig.Cands)
			b.sock.OnMsg = b.onPacket
			b.send("answer", b.cands)
			b.punch()
		})
	}
	if sig.SessionID != b.session {
		return
	}
	switch sig.What {
	case "offer":
	case "answer":
		b.peerCand = &sig.Cands[0]
		b.report.RemoteDisc = discoveryFromCands(sig.Cands)
		b.punch()
	case "candidates":
		// baseline ignores trickle relay candidates arriving late
	}
}

func (b *BaselineStrategy) punch() {
	if b.peerCand == nil || b.disc == nil || b.state == "connected" {
		return
	}
	b.state = "check"
	dst := sim.Endpoint{IP: b.peerCand.IP, Port: b.peerCand.Port, Proto: sim.UDP}
	fire := func() {}
	fire = func() {
		if b.state == "connected" || b.tries >= checkRTX {
			if b.state != "connected" {
				b.h.Logf("ice", "baseline punching failed after %d tries", b.tries)
				b.relayFallback()
			}
			return
		}
		b.tries++
		b.h.Send(b.sock, dst, &sim.ConnCheck{SessionID: b.session, Use: b.role == "initiator"}, 90)
		b.report.Attempts = append(b.report.Attempts, CheckAttempt{
			T: b.h.Engine().Now, Local: b.sock.ep(b.h.ID()).String(), Remote: dst.String(),
			Proto: "UDP", Kind: "srflx-srflx", Result: "sent",
		})
		b.h.Engine().ScheduleFunc(checkTimeout, fire)
	}
	fire()
}

func (b *BaselineStrategy) onPacket(e *sim.Engine, p *sim.Packet) {
	switch m := p.Msg.(type) {
	case *sim.ConnCheck:
		if m.SessionID != b.session {
			return
		}
		b.h.Send(b.sock, p.Src, &sim.ConnCheckAck{SessionID: b.session}, 90)
		// naive client: only accept the exact signaled srflx endpoint, no
		// peer-reflexive learning and no port prediction
		if b.peerCand != nil && p.Src.IP == b.peerCand.IP && p.Src.Port == b.peerCand.Port {
			b.win(p.Src)
		}
	case *sim.ConnCheckAck:
		if m.SessionID == b.session && b.peerCand != nil &&
			p.Src.IP == b.peerCand.IP && p.Src.Port == b.peerCand.Port {
			b.win(p.Src)
		}
	case *sim.RelayData:
		b.report.RelayBytes += int64(m.Bytes)
	case *sim.AppData:
		b.report.DirectBytes += int64(m.Bytes)
	}
}

func (b *BaselineStrategy) win(src sim.Endpoint) {
	if b.state == "connected" {
		return
	}
	b.state = "connected"
	b.report.Success = true
	b.report.Via = "direct"
	b.report.ConnectTime = e_now(b.h) - b.startAt
	b.report.Protocol = "UDP"
	b.report.WinningPath = b.sock.ep(b.h.ID()).String() + " <-> " + src.String()
	b.h.Logf("ice", "baseline DIRECT in %dms", b.report.ConnectTime.Milliseconds())
	b.h.OnConnected(ConnectedEvent{Via: "direct", Path: b.report.WinningPath, Protocol: "UDP",
		ConnectTime: b.report.ConnectTime})
	b.appTraffic(false)
}

// relayFallback picks the first configured relay regardless of location/load.
func (b *BaselineStrategy) relayFallback() {
	relays := b.h.Relays()
	if len(relays) == 0 {
		b.state = "done"
		b.h.OnConnected(ConnectedEvent{Via: "none"})
		return
	}
	r := relays[0]
	b.relaySrv = r
	rtt := b.h.TraceRTT(r.IP(), sim.UDP)
	b.report.RelayChoices = append(b.report.RelayChoices, RelayChoice{
		T: b.h.Engine().Now, Relay: r.ID(), Region: r.Location().Region, ISP: r.Location().ISP,
		LoadPct: r.LoadPct(), ProbeRTT: rtt, Chosen: true, Reason: "first available (no selection logic)",
	})
	b.h.Logf("ice", "baseline relay fallback: blindly chose %s", r.ID())
	dst := sim.Endpoint{Node: r.ID(), IP: r.IP(), Port: 3478, Proto: sim.UDP}
	b.h.Send(b.sock, dst, &sim.RelayAlloc{SessionID: b.session, Client: b.h.ID(), Proto: sim.UDP}, 100)
	b.sock.OnMsg = func(e *sim.Engine, p *sim.Packet) {
		if ack, ok := p.Msg.(*sim.RelayAllocAck); ok {
			b.relayEP = sim.Endpoint{Node: r.ID(), IP: ack.RelayIP, Port: ack.RelayPort, Proto: sim.UDP}
			b.state = "connected"
			b.report.Success = true
			b.report.Via = "relay"
			b.report.ConnectTime = e_now(b.h) - b.startAt
			b.report.Protocol = "UDP"
			b.report.WinningPath = "relay:" + r.ID()
			b.h.OnConnected(ConnectedEvent{Via: "relay", Path: b.report.WinningPath, Protocol: "UDP",
				ConnectTime: b.report.ConnectTime, RelayNode: r.ID()})
			b.appTraffic(true)
			return
		}
		b.onPacket(e, p)
	}
}

func (b *BaselineStrategy) appTraffic(viaRelay bool) {
	const chunk = 1200
	fire := func() {}
	fire = func() {
		if b.state == "done" {
			return
		}
		if viaRelay {
			if b.relayEP.IP != "" {
				b.h.Send(b.sock, b.relayEP, &sim.RelayData{SessionID: b.session, Bytes: chunk}, chunk)
				b.report.RelayBytes += chunk
			}
		} else if b.peerCand != nil {
			b.h.Send(b.sock, sim.Endpoint{IP: b.peerCand.IP, Port: b.peerCand.Port, Proto: sim.UDP},
				&sim.AppData{SessionID: b.session, Bytes: chunk}, chunk)
			b.report.DirectBytes += chunk
		}
		b.appTimer = b.h.Engine().ScheduleFunc(20*time.Millisecond, fire)
	}
	b.appTimer = b.h.Engine().ScheduleFunc(20*time.Millisecond, fire)
}

// NetworkChanged: baseline has no ICE restart; the old path simply dies.
func (b *BaselineStrategy) NetworkChanged(h Host) {
	if b.report.Success {
		b.report.Restarts++
		h.Logf("ice", "baseline: network changed but no renegotiation support, connection lost")
		b.report.Reconnected = false
	}
}

func e_now(h Host) time.Duration { return h.Engine().Now }
