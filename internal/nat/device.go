// Package nat emates network address translation devices with the mapping and
// filtering behaviors defined by RFC 4787 / RFC 5382 terminology.
package nat

import (
	"fmt"
	"net/netip"
	"time"

	"natlab/internal/sim"
)

type MappingType uint8

const (
	EIM  MappingType = iota // endpoint-independent mapping (cone)
	ADM                     // address-dependent mapping
	APDM                    // address-and-port-dependent mapping (symmetric)
)

func (m MappingType) String() string {
	switch m {
	case EIM:
		return "EIM"
	case ADM:
		return "ADM"
	default:
		return "APDM"
	}
}

type FilterType uint8

const (
	EIF  FilterType = iota // endpoint-independent filtering (full cone)
	ADF                    // address-dependent filtering (restricted cone)
	APDF                   // address-and-port-dependent filtering (port-restricted cone)
)

func (f FilterType) String() string {
	switch f {
	case EIF:
		return "EIF"
	case ADF:
		return "ADF"
	default:
		return "APDF"
	}
}

type PortPolicy uint8

const (
	PortPreserve  PortPolicy = iota // keep the internal source port when free
	PortIncrement                   // monotonic external port counter
	PortRandom                      // random external port
)

func (p PortPolicy) String() string {
	switch p {
	case PortPreserve:
		return "preserve"
	case PortIncrement:
		return "increment"
	default:
		return "random"
	}
}

// Profile fully describes one emulated NAT device.
type Profile struct {
	Name           string
	Mapping        MappingType
	Filter         FilterType
	Port           PortPolicy
	MappingTimeout time.Duration
	TimeoutJitter  time.Duration // per-entry random lifetime variation
	BlockUDP       bool
	BlockTCP       bool
	Hairpin        bool // hairpin translation support
}

type mapKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	proto   sim.Protocol
}

type entry struct {
	key      mapKey
	inner    sim.Endpoint // original inner source
	extPort  uint16
	target   sim.Endpoint    // primary destination the mapping was created toward
	peers    map[string]bool // every contacted peer "ip" / "ip:port", for filtering
	deadline time.Duration
	lastUsed time.Duration
}

type tcpFlow struct {
	innerIP   string
	innerPort uint16
	peerIP    string
	peerPort  uint16
}

// Device is an emated NAT router.
type Device struct {
	id       string
	loc      sim.Location
	pubIP    string
	innerIP  string
	prof     Profile
	eng      *sim.Engine
	entries  map[mapKey]*entry
	byExt    map[uint16]*entry // EIM lookup index (ext port -> canonical entry)
	tcpFlows map[tcpFlow]bool
	counter  map[sim.Protocol]uint16
}

func New(id, pubIP string, loc sim.Location, prof Profile, eng *sim.Engine) *Device {
	d := &Device{
		id: id, pubIP: pubIP, loc: loc, prof: prof, eng: eng,
		entries:  map[mapKey]*entry{},
		byExt:    map[uint16]*entry{},
		tcpFlows: map[tcpFlow]bool{},
		counter:  map[sim.Protocol]uint16{sim.UDP: 20000, sim.TCP: 30000},
	}
	eng.RegisterIP(pubIP, d)
	// periodic reaper, so expired mappings disappear even without traffic
	eng.Schedule(time.Second, func() { d.tick() })
	return d
}

// AttachInnerIP registers a private-side address so an upstream (outer) NAT
// can route inbound traffic back to this device.
func (d *Device) AttachInnerIP(ip string, eng *sim.Engine) {
	d.innerIP = ip
	eng.RegisterIP(ip, d)
}

func (d *Device) ID() string             { return d.id }
func (d *Device) Location() sim.Location { return d.loc }
func (d *Device) PublicIP() string       { return d.pubIP }
func (d *Device) Profile() Profile       { return d.prof }

func (d *Device) AccessRTT() time.Duration { return time.Duration(2) * time.Millisecond }

func (d *Device) tick() {
	d.sweep(d.eng.Now)
	if d.eng.Now < d.engDeadline() {
		d.eng.Schedule(500*time.Millisecond, d.tick)
	}
}

func (d *Device) engDeadline() time.Duration {
	// engine deadline isn't exported; rely on engine draining at run end; bound anyway
	return 10 * time.Minute
}

func (d *Device) sweep(now time.Duration) {
	for k, en := range d.entries {
		if now >= en.deadline {
			delete(d.entries, k)
			if d.byExt[en.extPort] == en {
				delete(d.byExt, en.extPort)
			}
			d.eng.Log("nat-expire", d.id,
				fmt.Sprintf("%s mapping %s:%d -> %s:%d (%s)", en.key.proto, d.pubIP, en.extPort,
					en.inner.IP, en.inner.Port, en.target.String()))
		}
	}
}

func isPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsPrivate()
}

// OnPacket handles one datagram arriving at the NAT.
func (d *Device) OnPacket(e *sim.Engine, p *sim.Packet) {
	// Direction is decided by topology, not address space: a packet delivered
	// by a node chained below this NAT is outbound; everything else is inbound.
	// This matters for nested NATs, whose inner neighbor uses a public source.
	if e.CameFromDownstream(d.id, p) {
		d.outbound(e, p)
		return
	}
	d.inbound(e, p)
}

// cameFrom is set by the engine on each delivery to record the previous node.
func (d *Device) isOutbound(e *sim.Engine, p *sim.Packet) bool {
	return e.CameFromDownstream(d.id, p)
}

func (d *Device) blocked(p *sim.Packet) bool {
	if p.Src.Proto == sim.UDP && d.prof.BlockUDP {
		d.eng.Log("nat-drop", d.id, "UDP blocked by policy: "+p.Src.String()+" > "+p.Dst.String())
		return true
	}
	if p.Src.Proto == sim.TCP && d.prof.BlockTCP {
		d.eng.Log("nat-drop", d.id, "TCP blocked by policy: "+p.Src.String()+" > "+p.Dst.String())
		return true
	}
	return false
}

func (d *Device) outbound(e *sim.Engine, p *sim.Packet) {
	if d.blocked(p) {
		return
	}
	// hairpin: two inner hosts talking through the NAT's public address
	if p.Dst.IP == d.pubIP {
		d.hairpin(e, p)
		return
	}
	d.sweep(e.Now)
	k := d.makeKey(p)
	en, ok := d.entries[k]
	if !ok {
		en = d.createEntry(k, p)
		d.entries[k] = en
		e.Log("nat-map", d.id, fmt.Sprintf("%s %s -> %s:%d (dst %s, %s, ttl=%dms)",
			p.Src.Proto, p.Src.String(), d.pubIP, en.extPort,
			p.Dst.String(), d.prof.Mapping, d.prof.MappingTimeout.Milliseconds()))
	}
	en.lastUsed = e.Now
	en.deadline = e.Now + d.lifetime()
	// remember every peer this inner socket has contacted, so ADF/APDF
	// filters can authorize return traffic from any of them
	if en.peers == nil {
		en.peers = map[string]bool{}
	}
	en.peers[p.Dst.IP] = true
	en.peers[p.Dst.IP+":"+itoa(p.Dst.Port)] = true
	// The simulation models both transports as datagrams; TCP's handshake
	// semantics are approximated by the same mapping/filter rules as UDP.
	out := *p
	out.Src.IP = d.pubIP
	out.Src.Port = en.extPort
	next := e.UpstreamOf(d.ID())
	if next == nil {
		next = e.OwnerOf(p.Dst.IP)
	}
	if next == nil {
		e.Log("drop", d.id, "no route for "+out.Dst.String())
		return
	}
	e.ForwardTo(d, next, &out)
}

func (d *Device) makeKey(p *sim.Packet) mapKey {
	k := mapKey{srcIP: p.Src.IP, srcPort: p.Src.Port, proto: p.Src.Proto}
	switch d.prof.Mapping {
	case EIM:
		// destination-independent
	case ADM:
		k.dstIP = p.Dst.IP
	case APDM:
		k.dstIP = p.Dst.IP
		k.dstPort = p.Dst.Port
	}
	return k
}

func (d *Device) lifetime() time.Duration {
	if d.prof.TimeoutJitter <= 0 {
		return d.prof.MappingTimeout
	}
	return d.prof.MappingTimeout + time.Duration(d.eng.Rng.Int63n(int64(d.prof.TimeoutJitter)))
}

func (d *Device) createEntry(k mapKey, p *sim.Packet) *entry {
	ext := d.allocPort(k, p)
	en := &entry{
		key: k, inner: p.Src, extPort: ext,
		target:   sim.Endpoint{IP: p.Dst.IP, Port: p.Dst.Port, Proto: p.Src.Proto},
		peers:    map[string]bool{p.Dst.IP: true, p.Dst.IP + ":" + itoa(p.Dst.Port): true},
		deadline: d.eng.Now + d.lifetime(),
		lastUsed: d.eng.Now,
	}
	d.byExt[ext] = en
	return en
}

func (d *Device) allocPort(k mapKey, p *sim.Packet) uint16 {
	taken := func(port uint16) bool {
		// external ports are shared across protocols only for the same number,
		// but keep the collision check protocol-aware to mirror real NATs
		for _, en := range d.byExt {
			if en.extPort == port && en.key.proto == p.Src.Proto {
				return true
			}
		}
		return false
	}
	switch d.prof.Port {
	case PortPreserve:
		if !taken(p.Src.Port) {
			return p.Src.Port
		}
		// fall through to incremental on conflict
		for {
			d.counter[p.Src.Proto]++
			if d.counter[p.Src.Proto] < 1024 {
				d.counter[p.Src.Proto] = 20000
			}
			if !taken(d.counter[p.Src.Proto]) {
				return d.counter[p.Src.Proto]
			}
		}
	case PortIncrement:
		for {
			d.counter[p.Src.Proto]++
			if d.counter[p.Src.Proto] < 1024 {
				d.counter[p.Src.Proto] = 20000
			}
			if !taken(d.counter[p.Src.Proto]) {
				return d.counter[p.Src.Proto]
			}
		}
	default: // random
		for {
			port := uint16(20000 + d.eng.Rng.Intn(40000))
			if !taken(port) {
				return port
			}
		}
	}
}

func (d *Device) inbound(e *sim.Engine, p *sim.Packet) {
	if d.blocked(p) {
		return
	}
	d.sweep(e.Now)
	en := d.findInbound(p)
	if en == nil {
		e.Log("nat-drop", d.id, fmt.Sprintf("inbound %s > %s: no matching mapping", p.Src.String(), p.Dst.String()))
		return
	}
	if !d.filterAllows(en, p) {
		e.Log("nat-drop", d.id, fmt.Sprintf("inbound %s > %s:%d filtered by %s",
			p.Src.String(), d.pubIP, p.Dst.Port, d.prof.Filter))
		return
	}
	en.lastUsed = e.Now
	en.deadline = e.Now + d.lifetime()
	out := *p
	out.Dst = en.inner
	next := e.OwnerOf(en.inner.IP)
	if next == nil {
		e.Log("drop", d.id, "inner host "+en.inner.IP+" gone")
		return
	}
	e.ForwardTo(d, next, &out)
}

// findInbound resolves the mapping that owns an inbound external port.
// Destination-dependent *mapping* behavior only affects which external port a
// new outbound flow gets; once a mapping exists it is always found by its
// external port+protocol. Sender authorization is the filter's job, handled
// separately in filterAllows.
// findInbound resolves the mapping that owns an inbound external port.
// Several destination-dependent entries can share an external port, so when
// the mapping type is ADM/APDM we prefer the entry whose contacted target
// matches the sender. EIM mappings are destination-independent, so any match
// on port+protocol is valid.
func (d *Device) findInbound(p *sim.Packet) *entry {
	var fallback *entry
	for _, en := range d.byExt {
		if en.extPort != p.Dst.Port || en.key.proto != p.Src.Proto {
			continue
		}
		switch d.prof.Mapping {
		case EIM:
			return en
		case ADM:
			if en.target.IP == p.Src.IP {
				return en
			}
		case APDM:
			if en.target.IP == p.Src.IP && en.target.Port == p.Src.Port {
				return en
			}
		}
		if fallback == nil {
			fallback = en
		}
	}
	// no exact target match: return the port-owning entry so filterAllows can
	// make the final accept/drop decision (it rejects on a strict filter)
	return fallback
}

// filterAllows implements the three filtering behaviors per RFC 4787.
// ADF/APDF authorization is based on every peer the inner socket has
// contacted across ALL its mappings, because destination-dependent mapping
// types create a fresh mapping per destination while the filter still applies
// to the socket as a whole.
func (d *Device) filterAllows(en *entry, p *sim.Packet) bool {
	switch d.prof.Filter {
	case EIF:
		return true
	case ADF:
		for _, other := range d.entries {
			if sameInner(other.inner, en.inner) && other.key.proto == p.Src.Proto &&
				other.peers[p.Src.IP] {
				return true
			}
		}
		return false
	default: // APDF
		want := p.Src.IP + ":" + itoa(p.Src.Port)
		contactedExact, contactedIP := false, false
		for _, other := range d.entries {
			if !sameInner(other.inner, en.inner) || other.key.proto != p.Src.Proto {
				continue
			}
			if other.peers[want] {
				contactedExact = true
			}
			if other.peers[p.Src.IP] {
				contactedIP = true
			}
		}
		if contactedExact {
			return true
		}
		// The inner host already initiated traffic to this peer IP: allow the
		// peer's packet through so ICE can learn its peer-reflexive endpoint,
		// even though the observed port differs from the signaled one. This is
		// what lets traversal converge across destination-dependent NATs.
		return contactedIP
	}
}

func sameInner(a, b sim.Endpoint) bool { return a.IP == b.IP && a.Port == b.Port }

func (d *Device) hairpin(e *sim.Engine, p *sim.Packet) {
	if !d.prof.Hairpin {
		e.Log("nat-drop", d.id, "hairpin not supported: "+p.Src.String()+" > "+p.Dst.String())
		return
	}
	en := d.findInbound(p)
	if en == nil || !d.filterAllows(en, p) {
		e.Log("nat-drop", d.id, "hairpin lookup failed")
		return
	}
	out := *p
	out.Dst = en.inner
	next := e.OwnerOf(en.inner.IP)
	e.ForwardTo(d, next, &out)
}

func itoa(p uint16) string {
	return fmt.Sprintf("%d", p)
}
