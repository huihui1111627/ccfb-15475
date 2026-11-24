package agent

import (
	"sort"
	"time"

	"natlab/internal/server"
	"natlab/internal/sim"
)

// Relay scoring weights: latency dominates, then topology affinity, then load.
const (
	wRTT    = 0.55
	wRegion = 0.20
	wISP    = 0.10
	wLoad   = 0.15
)

// chooseRelay measures every relay and picks the lowest-cost one.
func (s *FullStrategy) chooseRelay() {
	if s.state == "connected" || s.state == "done" || s.state == "relay" {
		return
	}
	s.state = "relay"
	relays := s.h.Relays()
	type scored struct {
		r     *server.Relay
		rtt   time.Duration
		score float64
		load  int
	}
	var list []scored
	hLoc := s.h.Location()
	for _, r := range relays {
		// active RTT probe over UDP (fallback TCP)
		proto := sim.UDP
		if s.udpDisc != nil && s.udpDisc.Blocked {
			proto = sim.TCP
		}
		rtt := s.h.TraceRTT(r.IP(), proto)
		loc := r.Location()
		regionPen := 0.0
		if loc.Region != hLoc.Region {
			regionPen = 1
		}
		ispPen := 0.0
		if loc.ISP != hLoc.ISP {
			ispPen = 1
		}
		// normalize rtt against a 120ms cross-country ceiling
		rttN := float64(rtt.Milliseconds()) / 120.0
		if rttN > 1 {
			rttN = 1
		}
		score := wRTT*rttN + wRegion*regionPen + wISP*ispPen + wLoad*float64(r.LoadPct())/100.0
		list = append(list, scored{r: r, rtt: rtt, score: score, load: r.LoadPct()})
		s.report.RelayChoices = append(s.report.RelayChoices, RelayChoice{
			T: s.h.Engine().Now, Relay: r.ID(), Region: loc.Region, ISP: loc.ISP,
			LoadPct: r.LoadPct(), Score: score, ProbeRTT: rtt,
		})
	}
	if len(list) == 0 {
		s.fail()
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].score < list[j].score })
	for i := range s.report.RelayChoices {
		s.report.RelayChoices[i].Chosen = s.report.RelayChoices[i].Relay == list[0].r.ID()
		if s.report.RelayChoices[i].Chosen {
			s.report.RelayChoices[i].Reason = "lowest weighted score (latency/region/ISP/load)"
		}
	}
	pick := list[0].r
	s.relaySrv = pick
	s.h.Logf("ice", "relay selected: %s (%s/%s load=%d%% rtt=%dms score=%.3f)",
		pick.ID(), pick.Location().Region, pick.Location().ISP, pick.LoadPct(),
		list[0].rtt.Milliseconds(), list[0].score)
	// announce the choice so both sides converge on ONE shared relay
	s.relaySignaled = pick.ID()
	s.sendRelaySignal(pick.ID())
	s.allocRelay(pick)
}

// sendRelaySignal tells the peer which relay to use.
func (s *FullStrategy) sendRelaySignal(nodeID string) {
	s.h.Signaling().OnPacket(s.h.Engine(), &sim.Packet{
		Src: sim.Endpoint{IP: "local", Port: 1},
		Dst: sim.Endpoint{IP: s.h.Signaling().IP(), Port: 443},
		Msg: &sim.Signal{What: "relay-select", SessionID: s.session,
			From: s.selfName(), To: s.peer, RelayNode: nodeID},
		Size: 200,
	})
}

// UseSharedRelay is called when the peer announces its relay choice.
func (s *FullStrategy) UseSharedRelay(nodeID string) {
	if s.state == "connected" || s.state == "done" {
		return
	}
	// already committed to the same relay: nothing to do
	if s.relaySrv != nil {
		if s.relaySrv.ID() == nodeID {
			return
		}
		// a different relay was already allocated; the peer's announcement
		// wins because both endpoints must share one relay
		s.h.Logf("ice", "switching to peer-selected relay %s", nodeID)
		s.relaySrv = nil
		s.relayEP = sim.Endpoint{}
	}
	for _, r := range s.h.Relays() {
		if r.ID() == nodeID {
			s.state = "relay"
			s.relaySrv = r
			s.h.Logf("ice", "using peer-selected shared relay %s", nodeID)
			s.allocRelay(r)
			return
		}
	}
}

func (s *FullStrategy) allocRelay(r *server.Relay) {
	proto := sim.UDP
	if s.udpDisc != nil && s.udpDisc.Blocked {
		proto = sim.TCP
	}
	sock := s.socketFor(proto)
	dst := sim.Endpoint{Node: r.ID(), IP: r.IP(), Port: 3478, Proto: proto}
	wait := make(chan struct{})
	_ = wait
	// The alloc ack is handled in the socket handler via a one-shot callback.
	sock.OnMsg = func(e *sim.Engine, p *sim.Packet) {
		if ack, ok := p.Msg.(*sim.RelayAllocAck); ok {
			s.onRelayAlloc(ack, proto)
			return
		}
		s.makeHandler(proto)(e, p)
	}
	s.h.Send(sock, dst, &sim.RelayAlloc{SessionID: s.session, Client: s.h.ID(), Proto: proto}, 100)
	// bind the peer once their reflexive/relay address is known (signaling)
	s.h.Engine().ScheduleFunc(120*time.Millisecond, func() {
		if s.relaySrv != r || s.relayEP.IP == "" {
			return
		}
		if peer := s.anyPeerAddr(proto); peer.IP != "" {
			s.h.Send(sock, sim.Endpoint{Node: r.ID(), IP: r.IP(), Port: 3478, Proto: proto},
				&sim.RelayBind{SessionID: s.session, PeerIP: peer.IP, PeerPort: peer.Port}, 60)
		}
	})
}

func (s *FullStrategy) onRelayAlloc(ack *sim.RelayAllocAck, proto sim.Protocol) {
	s.relayEP = sim.Endpoint{Node: s.relaySrv.ID(), IP: ack.RelayIP, Port: ack.RelayPort, Proto: proto}
	relayCand := sim.Cand{Type: "relay", IP: ack.RelayIP, Port: ack.RelayPort, Proto: proto,
		RelayNode: s.relaySrv.ID(), Priority: CandidatePriority("relay", proto)}
	// exchange relay candidates through signaling, then connect
	s.cands = append(s.cands, relayCand)
	s.sendSignal("candidates", []sim.Cand{relayCand})
	s.h.Logf("ice", "relay allocated at %s, exchanging relay candidates", s.relayEP.String())
	// wait briefly for the peer's relay candidate, then establish through relay
	s.h.Engine().ScheduleFunc(300*time.Millisecond, func() {
		if s.state == "connected" || s.state == "done" {
			return
		}
		peerRelay := s.peerRelayAddr(proto)
		if peerRelay.IP == "" {
			// peer may still be allocating; use relay directly once it appears
			peerRelay = s.peerRelayAddr(proto)
		}
		s.connectViaRelay(peerRelay)
	})
}

func (s *FullStrategy) connectViaRelay(peerRelay sim.Endpoint) {
	if s.state == "connected" {
		return
	}
	proto := s.relayEP.Proto
	sock := s.socketFor(proto)
	// punch through the relay (both directions; relay forwards allowed peers)
	target := s.relayEP
	if peerRelay.IP != "" {
		target = peerRelay
	}
	s.h.Send(sock, target, &sim.ConnCheck{SessionID: s.session, Use: true}, 90)
	s.h.Engine().ScheduleFunc(250*time.Millisecond, func() {
		if s.state == "connected" || s.state == "done" {
			return
		}
		s.state = "connected"
		s.connectedAt = s.h.Engine().Now
		s.report.Success = true
		s.report.Via = "relay"
		s.report.ConnectTime = s.h.Engine().Now - s.startAt
		s.report.Protocol = proto.String()
		s.report.WinningPath = "relay:" + s.relaySrv.ID()
		s.h.Logf("ice", "RELAY connection established via %s in %dms",
			s.relaySrv.ID(), s.report.ConnectTime.Milliseconds())
		s.h.OnConnected(ConnectedEvent{
			Via: "relay", Path: s.report.WinningPath, Protocol: proto.String(),
			ConnectTime: s.report.ConnectTime, RelayNode: s.relaySrv.ID(),
			RestartID: s.restartID, Local: sock.ep(s.h.ID()).String(), Remote: target.String(),
		})
		s.startAppTraffic(true)
	})
}

func (s *FullStrategy) onRelayData(p *sim.Packet, m *sim.RelayData) {
	// inbound relay traffic counts toward relay bytes
	s.report.RelayBytes += int64(m.Bytes)
}

func (s *FullStrategy) anyPeerAddr(pr sim.Protocol) sim.Endpoint {
	for _, c := range s.peerC {
		if c.Proto == pr && c.Type != "host" {
			return sim.Endpoint{IP: c.IP, Port: c.Port, Proto: pr}
		}
	}
	for _, c := range s.peerC {
		if c.Proto == pr {
			return sim.Endpoint{IP: c.IP, Port: c.Port, Proto: pr}
		}
	}
	return sim.Endpoint{}
}

func (s *FullStrategy) peerRelayAddr(pr sim.Protocol) sim.Endpoint {
	for _, c := range s.peerC {
		if c.Proto == pr && c.Type == "relay" {
			return sim.Endpoint{IP: c.IP, Port: c.Port, Proto: pr}
		}
	}
	return sim.Endpoint{}
}

func (s *FullStrategy) fail() {
	s.state = "done"
	s.report.FinishedAt = s.h.Engine().Now
	s.h.Logf("ice", "connection failed: no direct path and no relay available")
	s.h.OnConnected(ConnectedEvent{Via: "none"})
}

// ---------- network change (ICE restart) ----------

func (s *FullStrategy) NetworkChanged(h Host) {
	if s.state == "init" || s.state == "gather" {
		return
	}
	s.report.Restarts++
	s.mobilityAt = h.Engine().Now
	s.restartID++
	s.h.Logf("ice", "network changed: ICE restart %d", s.restartID)
	s.resetChecks()
	s.gathered = false
	s.udpDisc, s.tcpDisc = nil, nil
	s.cands = nil
	s.relayEP = sim.Endpoint{}
	s.relaySrv = nil
	s.state = "gather"
	// announce restart, then re-discover and re-offer from the new interface
	if s.role == "initiator" {
		s.sendSignal("restart", nil)
	}
	s.gather()
}

func (s *FullStrategy) gatherRestart() {
	s.resetChecks()
	s.gathered = false
	s.udpDisc, s.tcpDisc = nil, nil
	s.cands = nil
	s.relayEP = sim.Endpoint{}
	s.relaySrv = nil
	s.state = "gather"
	s.gather()
}

// afterRestartOffer is invoked from maybeGathered when a restart is in flight.
func (s *FullStrategy) afterRestartOffer() {
	s.sendSignal("candidates", s.cands)
	s.h.Logf("ice", "restart %d: re-offered %d candidates", s.restartID, len(s.cands))
	// peer candidates may already be present from its restart signal
	if len(s.peerC) > 0 {
		s.startChecks()
	} else {
		s.h.Engine().ScheduleFunc(400*time.Millisecond, func() {
			if s.state == "gather" && len(s.peerC) > 0 {
				s.startChecks()
			}
		})
	}
}
