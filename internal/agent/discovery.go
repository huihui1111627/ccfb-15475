package agent

import (
	"sort"
	"time"

	"natlab/internal/nat"
	"natlab/internal/sim"
)

// DiscoveryResult is what one terminal learns about its network position.
type DiscoveryResult struct {
	Proto         sim.Protocol
	OK            bool
	Blocked       bool
	ExternalIP    string
	ExternalPort  uint16
	Mapping       nat.MappingType
	Filter        nat.FilterType
	PortPolicy    nat.PortPolicy
	PortDelta     int // mean external port step for incrementing APDM devices
	Samples       []uint16
	RTT           map[string]time.Duration
	FilterOpen    bool // unsolicited packet from an alternate server addr got through
	SameIPAltPort bool // reply from same IP / alternate port got through
}

const (
	discTimeout = 350 * time.Millisecond
	discMaxRTX  = 3
	discSteps   = 5
)

// Probe plan. Every reply is sent back FROM the address the request was sent
// TO, so the NAT filter (which only allows packets from contacted addresses)
// never eats the response:
//
//	0 primary IP/port            -> reflexive tuple T0; server also fires an
//	                                 unsolicited probe from alt IP+alt port
//	1 primary IP/alt port        -> T1 (mapping dependence on dest port)
//	2 alt IP/primary port        -> T2 (mapping dependence on dest IP)
//	3 primary IP/port            -> T3 (4th reflexive port sample)
//	4 primary IP/port, ask the server to additionally reply from alt port of
//	  the SAME primary IP        -> ADF vs APDF disambiguation
type discState struct {
	host      Host
	proto     sim.Protocol
	sock      *Socket
	flow      uint32
	step      int
	rtx       int
	cancel    func()
	done      func(*DiscoveryResult)
	res       DiscoveryResult
	t0        sim.Endpoint
	t1        sim.Endpoint
	t2        sim.Endpoint
	t3        sim.Endpoint
	got       [discSteps]bool
	sentAt    map[int]time.Duration
	filterOK  bool
	altPortOK bool
}

var discSeq uint32

// RunDiscovery performs the full STUN-like behavioral test over one protocol.
// It returns the socket carrying the discovered reflexive mapping, so callers
// can run connectivity checks over the same 5-tuple (and thus the same NAT
// mapping). The result is delivered asynchronously via done on the virtual clock.
func RunDiscovery(h Host, proto sim.Protocol, done func(*DiscoveryResult)) *Socket {
	discs := h.DiscoveryServers()
	if len(discs) == 0 {
		done(&DiscoveryResult{Proto: proto})
		return nil
	}
	discSeq++
	st := &discState{
		host: h, proto: proto, flow: discSeq, done: done,
		sentAt: map[int]time.Duration{},
		res:    DiscoveryResult{Proto: proto, RTT: map[string]time.Duration{}},
	}
	st.sock = h.OpenSocket(proto, st.onPacket)
	h.Logf("disc", "start %s discovery via %s", proto, discs[0].ID())
	st.advance()
	return st.sock
}

func (st *discState) advance() {
	if st.step >= discSteps {
		st.finish()
		return
	}
	srv := st.host.DiscoveryServers()[0]
	ip1, ip2, p1, p2 := srv.Addrs()
	req := &sim.DiscReq{FlowID: st.flow}
	dstIP, dstPort := ip1, p1
	switch st.step {
	case 1:
		// same IP, alternate destination port (first port-dependence sample)
		dstPort = p2
	case 2:
		// alternate destination IP (address-dependence sample)
		dstIP = ip2
	case 3:
		// same IP, alternate port again (independent port-dependence sample
		// that must reach a different destination than step 0)
		dstPort = p2
	case 4:
		// request goes to primary, but ask for an extra same-IP alt-port reply
		req.ChangePort = true
	}
	// behavioral probes reply from addresses the NAT already expects, so a
	// missing answer means real loss/unreachability — one shot is enough
	maxRTX := discMaxRTX
	if st.step >= 1 {
		maxRTX = 1
	}
	if st.rtx >= maxRTX {
		if st.step == 0 {
			st.res.Blocked = true
			st.done(&st.res)
			return
		}
		st.host.Logf("disc", "step %d no reply, advancing", st.step)
		st.step++
		st.rtx = 0
		st.advance()
		return
	}
	dst := sim.Endpoint{Node: srv.ID(), IP: dstIP, Port: dstPort, Proto: st.proto}
	st.host.Logf("disc", "step %d rtx %d: probe -> %s", st.step, st.rtx, dst.String())
	st.sentAt[st.step] = st.host.Engine().Now
	st.host.Send(st.sock, dst, req, 80)
	st.cancel = st.host.Engine().ScheduleFunc(discTimeout, func() {
		st.rtx++
		st.advance()
	})
}

func (st *discState) onPacket(e *sim.Engine, p *sim.Packet) {
	switch m := p.Msg.(type) {
	case *sim.DiscResp:
		if m.FlowID != st.flow {
			return
		}
		// only the "primary" response of a step drives the state machine and
		// cancels the timeout; secondary same-IP alt-port replies just record
		// the filter verdict.
		isSecondary := st.step == 4 && p.Src.Port != st.host.DiscoveryServers()[0].PrimaryPort()
		if !isSecondary && st.cancel != nil {
			st.cancel()
			st.cancel = nil
		}
		obs := sim.Endpoint{IP: m.ObservedIP, Port: m.Observed, Proto: st.proto}
		srvID := st.host.DiscoveryServers()[0].ID()
		if rtt, ok := st.res.RTT[srvID]; !ok || rtt == 0 {
			st.res.RTT[srvID] = e.Now - st.sentAt[st.step]
		}
		if isSecondary {
			st.altPortOK = true
			st.res.SameIPAltPort = true
			st.host.Logf("disc", "same-IP alternate-port reply accepted (ADF)")
			return
		}
		switch st.step {
		case 0:
			st.t0 = obs
			st.res.ExternalIP, st.res.ExternalPort = obs.IP, obs.Port
			st.res.Samples = append(st.res.Samples, obs.Port)
		case 1:
			st.t1 = obs
			st.res.Samples = append(st.res.Samples, obs.Port)
		case 2:
			st.t2 = obs
			st.res.Samples = append(st.res.Samples, obs.Port)
		case 3:
			st.t3 = obs
			st.res.Samples = append(st.res.Samples, obs.Port)
		case 4:
			// primary-port reply of step 4 supplies the last port sample
			st.res.Samples = append(st.res.Samples, obs.Port)
		}
		st.got[st.step] = true
		st.step++
		st.rtx = 0
		st.advance()
	case *sim.FilterProbe:
		if m.FlowID != st.flow {
			return
		}
		st.filterOK = true
		st.res.FilterOpen = true
		st.host.Logf("disc", "unsolicited probe from alternate address accepted (EIF)")
	}
}

func (st *discState) finish() {
	res := &st.res
	res.OK = st.got[0]
	if !res.OK {
		res.Blocked = true
		st.done(res)
		return
	}
	// Mapping classification from two discriminating probes (RFC 4787):
	//   step2 -> alternate server IP            (t2 vs t0)
	//   step3 -> alternate port, SAME server IP (t3 vs t0)
	//
	//   EIM : neither probe changes the reflexive tuple
	//   ADM : changing the destination IP changes it, but changing only the
	//         destination port on the same IP does not
	//   APDM: changing only the destination port already changes it
	//
	// A probe that never answers is treated as "tuple changed" (the safe
	// restrictive reading), since a NAT that swallows the response cannot be
	// assumed destination-independent.
	ipDependent := !st.got[2] || !sameTuple(st.t2, st.t0)
	portDependent := !st.got[3] || !sameTuple(st.t3, st.t0)
	switch {
	case !portDependent && !ipDependent:
		res.Mapping = nat.EIM
	case portDependent:
		res.Mapping = nat.APDM
	default: // ipDependent but not portDependent
		res.Mapping = nat.ADM
	}
	// filtering behavior. The unsolicited alt-IP/alt-port probe is the
	// strongest test: if it passes, the filter is endpoint-independent and
	// the same-IP alt-port reply naturally passes as well.
	switch {
	case st.filterOK:
		res.Filter = nat.EIF
	case st.altPortOK:
		res.Filter = nat.ADF
	default:
		res.Filter = nat.APDF
	}
	if res.Mapping == nat.APDM && res.Filter == nat.EIF {
		res.Filter = nat.ADF // symmetric NATs cannot be full-cone
	}
	res.PortPolicy, res.PortDelta = classifyPorts(res.Samples, st.sock.Port)
	st.host.Logf("disc", "result mapping=%s filter=%s ports=%s ext=%s:%d delta=%d",
		res.Mapping, res.Filter, res.PortPolicy, res.ExternalIP, res.ExternalPort, res.PortDelta)
	st.done(res)
}

func sameTuple(a, b sim.Endpoint) bool { return a.IP == b.IP && a.Port == b.Port }

func classifyPorts(samples []uint16, localPort uint16) (nat.PortPolicy, int) {
	if len(samples) < 2 {
		return nat.PortPreserve, 0
	}
	// preserve: the reflexive port for the primary destination equals the
	// local port (first sample), and the device does not follow a single
	// consistent increasing sequence across all destinations
	if samples[0] == localPort {
		// still check whether later samples form a clean increment sequence;
		// if not, this is preservation with per-destination fallback
		fresh := dedupOrdered(samples)
		if len(fresh) >= 2 {
			if pol, delta, ok := tryIncrement(fresh); ok {
				return pol, delta
			}
		}
		return nat.PortPreserve, 0
	}
	fresh := dedupOrdered(samples)
	if len(fresh) >= 2 {
		if pol, delta, ok := tryIncrement(fresh); ok {
			return pol, delta
		}
	}
	return nat.PortRandom, 0
}

// dedupOrdered removes repeated values while preserving first-seen order.
func dedupOrdered(in []uint16) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// tryIncrement recognizes an incrementing allocator even when an inner NAT
// occasionally consumes an intervening port or reorders samples. The decisive
// signal is tight, small steps: a counter increments by a handful of ports,
// whereas a randomized allocator jumps across a wide port range (steps in the
// thousands with high dispersion).
func tryIncrement(fresh []uint16) (nat.PortPolicy, int, bool) {
	if len(fresh) < 2 {
		return nat.PortRandom, 0, false
	}
	var deltas []int
	positive := 0
	for i := 1; i < len(fresh); i++ {
		d := int(fresh[i]) - int(fresh[i-1])
		if d > 0 {
			deltas = append(deltas, d)
			if d <= maxIncrementStep {
				positive++
			}
		}
	}
	if positive*2 < len(fresh)-1 {
		return nat.PortRandom, 0, false // most steps are large/non-positive: random
	}
	if len(deltas) == 0 {
		return nat.PortRandom, 0, false
	}
	sort.Ints(deltas)
	med := deltas[len(deltas)/2]
	if med <= 0 || med > maxIncrementStep {
		return nat.PortRandom, 0, false
	}
	return nat.PortIncrement, med, true
}

// maxIncrementStep bounds the median gap that still reads as a counter-based
// allocator rather than randomized port assignment.
const maxIncrementStep = 64

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
