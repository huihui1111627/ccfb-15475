// Package agent implements the connection-establishment logic running on
// emulated terminals: discovery, candidate gathering, connectivity checks,
// relay fallback, keep-alives and renegotiation after network changes.
package agent

import (
	"fmt"
	"time"

	"natlab/internal/server"
	"natlab/internal/sim"
)

// Socket is one local transport socket (IP/port/proto) with a packet handler.
type Socket struct {
	IP    string
	Port  uint16
	Proto sim.Protocol
	OnMsg func(e *sim.Engine, p *sim.Packet)
}

func (s Socket) ep(node string) sim.Endpoint {
	return sim.Endpoint{Node: node, IP: s.IP, Port: s.Port, Proto: s.Proto}
}

// Host is what a strategy needs from its terminal.
type Host interface {
	ID() string
	Engine() *sim.Engine
	Location() sim.Location
	AccessRTT() time.Duration
	OpenSocket(proto sim.Protocol, onMsg func(*sim.Engine, *sim.Packet)) *Socket
	Send(s *Socket, dst sim.Endpoint, msg sim.Msg, size int)
	Signaling() *server.Signaling
	DiscoveryServers() []*server.Discovery
	Relays() []*server.Relay
	Logf(kind, format string, args ...any)
	TraceRTT(targetIP string, proto sim.Protocol) time.Duration
	NetworkSwitch(now time.Duration)
	OnConnected(ev ConnectedEvent)
}

// Strategy is a connection-establishment algorithm (full or baseline).
type Strategy interface {
	Name() string
	// Begin starts discovery + offer/answer for a session with peerID.
	Begin(h Host, sessionID, peerID string)
	OnSignal(h Host, s *sim.Signal)
	OnPacket(h Host, p *sim.Packet)
	// NetworkChanged triggers renegotiation (ICE restart).
	NetworkChanged(h Host)
	Report() RunReport
}

// Terminal is an emulated end host.
type Terminal struct {
	id        string
	eng       *sim.Engine
	loc       sim.Location
	access    time.Duration
	lanIP     string
	sockets   map[socketKey]*Socket
	portAlloc uint16
	sig       *server.Signaling
	discovery []*server.Discovery
	relays    []*server.Relay
	strategy  Strategy
	gatewayID string
	// mobility emulation
	siteName   string
	mobilityAt time.Duration
	mobilityTo MobilityTarget
	lastEvent  ConnectedEvent
	eventFired bool
	signalName string
}

type socketKey struct {
	port  uint16
	proto sim.Protocol
}

// MobilityTarget describes a Wi-Fi/cellular handoff.
type MobilityTarget struct {
	NewLANIP   string
	NewGateway string // node id of the new outer NAT chain (rebuilt by scenario)
}

func NewTerminal(id string, loc sim.Location, accessRTT time.Duration, lanIP string,
	gatewayID string, eng *sim.Engine) *Terminal {
	t := &Terminal{
		id: id, eng: eng, loc: loc, access: accessRTT, lanIP: lanIP,
		sockets:    map[socketKey]*Socket{},
		portAlloc:  40000,
		gatewayID:  gatewayID,
		mobilityAt: -1,
	}
	eng.RegisterIP(lanIP, t)
	return t
}

func (t *Terminal) ID() string               { return t.id }
func (t *Terminal) Location() sim.Location   { return t.loc }
func (t *Terminal) AccessRTT() time.Duration { return t.access }
func (t *Terminal) Engine() *sim.Engine      { return t.eng }
func (t *Terminal) LANIP() string            { return t.lanIP }
func (t *Terminal) GatewayID() string        { return t.gatewayID }

// BindServices connects the terminal to the infrastructure servers.
func (t *Terminal) BindServices(sig *server.Signaling, discs []*server.Discovery, relays []*server.Relay) {
	t.sig = sig
	t.discovery = discs
	t.relays = relays
	sig.Register(t.SignalName(), t)
}

func (t *Terminal) SetStrategy(s Strategy) { t.strategy = s }
func (t *Terminal) Strategy() Strategy     { return t.strategy }

func (t *Terminal) Signaling() *server.Signaling          { return t.sig }
func (t *Terminal) DiscoveryServers() []*server.Discovery { return t.discovery }
func (t *Terminal) Relays() []*server.Relay               { return t.relays }

// SetSignalName sets the stable logical name used to register with signaling.
func (t *Terminal) SetSignalName(name string) { t.signalName = name }

// SignalName returns the name the signaling server knows this terminal by.
func (t *Terminal) SignalName() string {
	if t.signalName != "" {
		return t.signalName
	}
	return t.id
}
func (t *Terminal) SetMobility(at time.Duration, target MobilityTarget) {
	t.mobilityAt = at
	t.mobilityTo = target
	t.eng.Schedule(at, func() { t.NetworkSwitch(at) })
}

// NetworkSwitch emulates changing networks: new LAN address, new upstream path.
func (t *Terminal) NetworkSwitch(now time.Duration) {
	t.eng.Log("mobility", t.id, "network handoff: "+t.lanIP+" -> "+t.mobilityTo.NewLANIP+" via "+t.mobilityTo.NewGateway)
	old := t.lanIP
	t.lanIP = t.mobilityTo.NewLANIP
	t.gatewayID = t.mobilityTo.NewGateway
	delete(t.eng.OwnerMap(), old)
	t.eng.RegisterIP(t.lanIP, t)
	gw := t.eng.NodeByID(t.mobilityTo.NewGateway)
	t.eng.SetUpstreamID(t.id, gw)
	// existing sockets keep their local port but move to the new interface;
	// outer NAT mappings are gone and will be rebuilt by traffic.
	for k, sk := range t.sockets {
		sk.IP = t.lanIP
		t.sockets[k] = sk
	}
	if t.strategy != nil {
		t.strategy.NetworkChanged(t)
	}
}

func (t *Terminal) OpenSocket(proto sim.Protocol, onMsg func(*sim.Engine, *sim.Packet)) *Socket {
	t.portAlloc += 1 + uint16(t.eng.Rng.Intn(4))
	sk := &Socket{IP: t.lanIP, Port: t.portAlloc, Proto: proto, OnMsg: onMsg}
	t.sockets[socketKey{sk.Port, proto}] = sk
	return sk
}

func (t *Terminal) Send(sk *Socket, dst sim.Endpoint, msg sim.Msg, size int) {
	t.eng.Emit(t, sk.ep(t.id), dst, msg, size)
}

func (t *Terminal) OnPacket(e *sim.Engine, p *sim.Packet) {
	sk, ok := t.sockets[socketKey{p.Dst.Port, p.Dst.Proto}]
	if !ok {
		e.Log("drop", t.id, fmt.Sprintf("no socket for %s (%s)", p.Dst.String(), sim.MsgName(p.Msg)))
		return
	}
	if sk.OnMsg != nil {
		sk.OnMsg(e, p)
		return
	}
	if t.strategy != nil {
		t.strategy.OnPacket(t, p)
	}
}

// OnSignal is the signaling-server callback.
func (t *Terminal) OnSignal(e *sim.Engine, s *sim.Signal) {
	t.strategy.OnSignal(t, s)
}

func (t *Terminal) Logf(kind, format string, args ...any) {
	t.eng.Log(kind, t.id, fmt.Sprintf(format, args...))
}

// OnConnected records the outcome reported by the strategy.
func (t *Terminal) OnConnected(ev ConnectedEvent) {
	t.lastEvent = ev
	t.eventFired = true
	t.eng.Log("connected", t.id, ev.Via+" via "+ev.Path)
}

// LastEvent returns the most recent connection outcome.
func (t *Terminal) LastEvent() (ConnectedEvent, bool) { return t.lastEvent, t.eventFired }

// TraceRTT emulates a path RTT measurement (half RTT each direction plus jitter).
func (t *Terminal) TraceRTT(targetIP string, proto sim.Protocol) time.Duration {
	n := t.eng.OwnerOf(targetIP)
	if n == nil {
		return 200 * time.Millisecond
	}
	d1, _ := t.eng.LinkPlan(t, n)
	d2, _ := t.eng.LinkPlan(n, t)
	return d1 + d2
}
