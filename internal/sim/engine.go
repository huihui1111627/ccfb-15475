package sim

import (
	"container/heap"
	"math/rand"
	"time"
)

// Protocol is the emulated transport protocol.
type Protocol uint8

const (
	UDP Protocol = 17
	TCP Protocol = 6
)

func (p Protocol) String() string {
	if p == TCP {
		return "TCP"
	}
	return "UDP"
}

// Endpoint is a packet source or destination.
type Endpoint struct {
	Node  string   `json:"node"`
	IP    string   `json:"ip"`
	Port  uint16   `json:"port"`
	Proto Protocol `json:"proto"`
}

func (e Endpoint) String() string { return e.IP + ":" + itoa(e.Port) + "/" + e.Proto.String() }

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}

// Msg is the payload interface. All concrete message types live across sim/server/agent.
type Msg interface{ msgTag() }

// Packet is a single datagram or TCP segment moving through the emulated network.
type Packet struct {
	UID     uint64   `json:"uid"`
	Src     Endpoint `json:"src"`
	Dst     Endpoint `json:"dst"`
	Msg     Msg      `json:"-"`
	Kind    string   `json:"kind"`
	Size    int      `json:"size"`
	lastHop string   // node id that handed this packet to the current receiver
}

// Location identifies where a node sits in the emulated topology.
type Location struct {
	Region string `json:"region"`
	ISP    string `json:"isp"`
}

// AccessNode is implemented by terminals whose last-mile link adds latency.
type AccessNode interface {
	AccessRTT() time.Duration
}

// Node is anything that can receive a packet.
type Node interface {
	ID() string
	Location() Location
	OnPacket(e *Engine, p *Packet)
}

type timedEvent struct {
	at        time.Duration
	seq       uint64
	fn        func()
	cancelled bool
}

type eventHeap []*timedEvent

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	return h[i].at < h[j].at || (h[i].at == h[j].at && h[i].seq < h[j].seq)
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(*timedEvent)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// TraceEvent is one recorded simulation event.
type TraceEvent struct {
	T      time.Duration `json:"t_ms"`
	Kind   string        `json:"kind"`
	Node   string        `json:"node,omitempty"`
	Detail string        `json:"detail"`
}

// Engine is the virtual network.
type Engine struct {
	Now      time.Duration
	Rng      *rand.Rand
	links    *LinkModel
	events   eventHeap
	seq      uint64
	pktSeq   uint64
	owners   map[string]Node // IP -> node
	nodes    map[string]Node // node id -> node
	upstream map[string]Node // node id -> next NAT toward the internet
	trace    []TraceEvent
	Record   bool
	deadline time.Duration
}

// NewEngine builds an engine with the given deterministic seed.
func NewEngine(seed int64, links *LinkModel) *Engine {
	return &Engine{
		Rng:      rand.New(rand.NewSource(seed)),
		links:    links,
		owners:   map[string]Node{},
		nodes:    map[string]Node{},
		upstream: map[string]Node{},
	}
}

// RegisterIP makes a node own an IP address.
func (e *Engine) RegisterIP(ip string, n Node) { e.owners[ip] = n }

// RegisterNode indexes a node by ID (needed for rewiring during mobility).
func (e *Engine) RegisterNode(n Node) { e.nodes[n.ID()] = n }

// NodeByID returns a registered node.
func (e *Engine) NodeByID(id string) Node { return e.nodes[id] }

// SetUpstream chains a NAT node behind another NAT / toward the internet.
func (e *Engine) SetUpstream(from, to Node) { e.upstream[from.ID()] = to }

// UpstreamOf returns the next NAT/device chained above a node, if any.
func (e *Engine) UpstreamOf(id string) Node { return e.upstream[id] }

// OwnerOf returns the node owning an IP, if any.
func (e *Engine) OwnerOf(ip string) Node { return e.owners[ip] }

// OwnerMap returns a copy of the IP-ownership table.
func (e *Engine) OwnerMap() map[string]Node {
	out := make(map[string]Node, len(e.owners))
	for k, v := range e.owners {
		out[k] = v
	}
	return out
}

// SetUpstreamID rewires a node's upstream path (used during network handoff).
func (e *Engine) SetUpstreamID(nodeID string, up Node) {
	if up == nil {
		delete(e.upstream, nodeID)
		return
	}
	e.upstream[nodeID] = up
}

// LinkPlan exposes the link model for RTT measurements.
func (e *Engine) LinkPlan(a, b Node) (time.Duration, bool) {
	return e.links.Plan(e.Rng, a, b, &Packet{Msg: &KeepAlive{}})
}

// Trace returns the recorded event log.
func (e *Engine) Trace() []TraceEvent { return e.trace }

func (e *Engine) Log(kind, node, detail string) {
	if e.Record {
		e.trace = append(e.trace, TraceEvent{T: e.Now, Kind: kind, Node: node, Detail: detail})
	}
}

// Schedule runs fn after the given virtual delay.
func (e *Engine) Schedule(delay time.Duration, fn func()) {
	if delay < 0 {
		delay = 0
	}
	e.seq++
	heap.Push(&e.events, &timedEvent{at: e.Now + delay, seq: e.seq, fn: fn})
}

// ScheduleFunc schedules fn and returns a cancel handle. Cancellation marks
// the event rather than mutating the heap, so heap invariants are preserved.
func (e *Engine) ScheduleFunc(delay time.Duration, fn func()) (cancel func()) {
	if delay < 0 {
		delay = 0
	}
	e.seq++
	ev := &timedEvent{at: e.Now + delay, seq: e.seq, fn: fn}
	heap.Push(&e.events, ev)
	return func() { ev.cancelled = true }
}

func (e *Engine) newPacket(src, dst Endpoint, msg Msg, size int) *Packet {
	e.pktSeq++
	return &Packet{UID: e.pktSeq, Src: src, Dst: dst, Msg: msg, Kind: MsgName(msg), Size: size}
}

// Emit sends a packet from a node into the emulated network. Outbound packets
// from nodes behind NATs are first handed to the upstream gateway.
func (e *Engine) Emit(from Node, src, dst Endpoint, msg Msg, size int) {
	p := e.newPacket(src, dst, msg, size)
	var receiver Node
	if up, ok := e.upstream[from.ID()]; ok {
		receiver = up // traverse the next NAT hop first
	} else {
		receiver = e.owners[dst.IP]
	}
	if receiver == nil {
		e.Log("drop", from.ID(), "no route to "+dst.String())
		return
	}
	e.deliver(from, receiver, p)
}

// ForwardTo hands an already-transformed packet to a specific next node
// (used by NATs for inbound translation and by relays).
func (e *Engine) ForwardTo(from, to Node, p *Packet) { e.deliver(from, to, p) }

func (e *Engine) deliver(from, to Node, p *Packet) {
	delay, lost := e.links.Plan(e.Rng, from, to, p)
	if lost {
		e.Log("drop", from.ID(), p.Kind+" lost on link -> "+to.ID()+" ("+p.Src.String()+" > "+p.Dst.String()+")")
		return
	}
	p.lastHop = from.ID()
	e.Log("send", from.ID(), p.Kind+" "+p.Src.String()+" -> "+p.Dst.String()+" via "+to.ID())
	pkt := *p
	e.Schedule(delay, func() {
		e.Log("recv", to.ID(), pkt.Kind+" from "+pkt.Src.String())
		to.OnPacket(e, &pkt)
	})
}

// CameFromDownstream reports whether a packet was delivered by a node chained
// below natID (i.e. it is leaving the private side of that NAT).
func (e *Engine) CameFromDownstream(natID string, p *Packet) bool {
	if p.lastHop == "" {
		return false
	}
	cur := p.lastHop
	seen := map[string]bool{}
	for cur != "" && !seen[cur] {
		seen[cur] = true
		up := e.UpstreamOf(cur)
		if up == nil {
			return false
		}
		if up.ID() == natID {
			return true
		}
		cur = up.ID()
	}
	return false
}

// Run processes events until the deadline or the queue drains.
func (e *Engine) Run(deadline time.Duration) {
	e.deadline = deadline
	for e.events.Len() > 0 {
		ev := e.events[0]
		if ev.at > deadline {
			break
		}
		heap.Pop(&e.events)
		if ev.cancelled {
			continue
		}
		e.Now = ev.at
		ev.fn()
	}
	if e.events.Len() == 0 {
		e.Now = deadline
	}
}

// Pending reports whether scheduled work remains.
func (e *Engine) Pending() bool { return e.events.Len() > 0 }
