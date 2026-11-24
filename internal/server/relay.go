package server

import (
	"fmt"
	"time"

	"natlab/internal/sim"
)

// Relay is a TURN-like media relay with capacity and measured load.
type Relay struct {
	id       string
	loc      sim.Location
	ip       string
	port     uint16
	capacity int
	load     int // active allocations
	bytes    int64
	sessions map[string]*relaySession
	peers    map[string]sim.Endpoint // session -> allowed peer endpoint
}

type relaySession struct {
	client sim.Endpoint
	relay  uint16
	proto  sim.Protocol
}

func NewRelay(id string, loc sim.Location, ip string, capacity int, eng *sim.Engine) *Relay {
	r := &Relay{
		id: id, loc: loc, ip: ip, port: 3478, capacity: capacity,
		sessions: map[string]*relaySession{}, peers: map[string]sim.Endpoint{},
	}
	eng.RegisterIP(ip, r)
	return r
}

func (r *Relay) ID() string               { return r.id }
func (r *Relay) Location() sim.Location   { return r.loc }
func (r *Relay) IP() string               { return r.ip }
func (r *Relay) AccessRTT() time.Duration { return 0 }
func (r *Relay) LoadPct() int {
	if r.capacity == 0 {
		return 0
	}
	return r.load * 100 / r.capacity
}
func (r *Relay) Bytes() int64        { return r.bytes }
func (r *Relay) ActiveSessions() int { return r.load }

func (r *Relay) OnPacket(e *sim.Engine, p *sim.Packet) {
	switch m := p.Msg.(type) {
	case *sim.RelayAlloc:
		if r.load >= r.capacity {
			e.Log("relay", r.id, "alloc rejected: at capacity")
			return
		}
		r.port++
		sess := &relaySession{client: p.Src, relay: r.port, proto: m.Proto}
		r.sessions[m.SessionID] = sess
		r.load++
		e.Log("relay", r.id, fmt.Sprintf("alloc %s relayed at %s:%d, load=%d%%",
			m.SessionID, r.ip, r.port, r.LoadPct()))
		ack := &sim.RelayAllocAck{RelayIP: r.ip, RelayPort: r.port, Load: r.LoadPct()}
		e.Emit(r,
			sim.Endpoint{Node: r.id, IP: r.ip, Port: 3478, Proto: p.Src.Proto},
			p.Src, ack, 80)
	case *sim.RelayBind:
		if sess, ok := r.sessions[m.SessionID]; ok {
			r.peers[m.SessionID] = sim.Endpoint{IP: m.PeerIP, Port: m.PeerPort, Proto: sess.proto}
			e.Log("relay", r.id, "bind peer "+m.PeerIP+":"+fmt.Sprintf("%d", m.PeerPort)+" for "+m.SessionID)
		}
	case *sim.RelayData:
		r.forward(e, p, m)
	}
}

func (r *Relay) forward(e *sim.Engine, p *sim.Packet, m *sim.RelayData) {
	sess, ok := r.sessions[m.SessionID]
	if !ok {
		return
	}
	r.bytes += int64(m.Bytes)
	// data from the allowed client is relayed to its peer, and vice versa
	var target sim.Endpoint
	relayEP := sim.Endpoint{Node: r.id, IP: r.ip, Port: sess.relay, Proto: sess.proto}
	if p.Src.IP == sess.client.IP && p.Src.Port == sess.client.Port {
		peer, ok := r.peers[m.SessionID]
		if !ok {
			return
		}
		target = peer
	} else {
		target = sess.client
	}
	out := sim.Packet{Src: relayEP, Dst: target, Msg: &sim.RelayData{SessionID: m.SessionID, Bytes: m.Bytes}, Kind: "RelayData", Size: m.Bytes}
	next := e.OwnerOf(target.IP)
	if next == nil {
		e.Log("drop", r.id, "relay peer gone")
		return
	}
	e.ForwardTo(r, next, &out)
}
