// Package server contains the emulated discovery (STUN-like), signaling and
// relay (TURN-like) servers.
package server

import (
	"fmt"
	"time"

	"natlab/internal/sim"
)

// Discovery is a STUN-like probe server reachable on two IPs / two ports.
type Discovery struct {
	id      string
	loc     sim.Location
	ips     [2]string
	ports   [2]uint16
	pending map[uint32]probeState
}

type probeState struct {
	from sim.Endpoint
	dead time.Duration
}

func NewDiscovery(id string, loc sim.Location, ip1, ip2 string, port1, port2 uint16, eng *sim.Engine) *Discovery {
	d := &Discovery{
		id: id, loc: loc, ips: [2]string{ip1, ip2}, ports: [2]uint16{port1, port2},
		pending: map[uint32]probeState{},
	}
	eng.RegisterIP(ip1, d)
	eng.RegisterIP(ip2, d)
	return d
}

func (d *Discovery) ID() string             { return d.id }
func (d *Discovery) Location() sim.Location { return d.loc }
func (d *Discovery) Addrs() (string, string, uint16, uint16) {
	return d.ips[0], d.ips[1], d.ports[0], d.ports[1]
}

// PrimaryPort returns the main listening port.
func (d *Discovery) PrimaryPort() uint16      { return d.ports[0] }
func (d *Discovery) ports0() uint16           { return d.ports[0] }
func (d *Discovery) AccessRTT() time.Duration { return 0 }

func (d *Discovery) OnPacket(e *sim.Engine, p *sim.Packet) {
	req, ok := p.Msg.(*sim.DiscReq)
	if !ok {
		return
	}
	send := func(ip string, port uint16, msg sim.Msg, size int) {
		src := sim.Endpoint{Node: d.id, IP: ip, Port: port, Proto: p.Src.Proto}
		dst := sim.Endpoint{Node: p.Src.Node, IP: p.Src.IP, Port: p.Src.Port, Proto: p.Src.Proto}
		e.Emit(d, src, dst, msg, size)
	}
	resp := &sim.DiscResp{
		FlowID: req.FlowID, ObservedIP: p.Src.IP, Observed: p.Src.Port,
		FromIP: p.Dst.IP, FromPort: p.Dst.Port,
		ChangedIP: d.otherIP(p.Dst.IP), ChangedUDP: d.otherPort(p.Dst.Port),
		RTTUs: (e.Now.Microseconds() - 0),
	}
	if req.ChangeIP || req.ChangePort {
		// reply from the requested alternate address
		ip, port := p.Dst.IP, p.Dst.Port
		if req.ChangeIP {
			ip = d.otherIP(ip)
		}
		if req.ChangePort {
			port = d.otherPort(port)
		}
		send(ip, port, resp, 96)
		return
	}
	// normal reflection response
	send(p.Dst.IP, p.Dst.Port, resp, 96)
	if _, armed := d.pending[req.FlowID]; !armed {
		d.pending[req.FlowID] = probeState{from: p.Src, dead: e.Now + 4*time.Second}
		// a probe from the alternate address tests the filter behavior
		go2 := sim.Endpoint{Node: d.id, IP: d.ips[1], Port: d.ports[1], Proto: p.Src.Proto}
		dst2 := sim.Endpoint{Node: p.Src.Node, IP: p.Src.IP, Port: p.Src.Port, Proto: p.Src.Proto}
		e.Schedule(15*time.Millisecond, func() {
			if st, ok := d.pending[req.FlowID]; ok && e.Now < st.dead {
				e.Emit(d, go2, dst2, &sim.FilterProbe{FlowID: req.FlowID, Token: req.FlowID ^ 0x5a5a}, 64)
			}
		})
	}
}

func (d *Discovery) otherIP(ip string) string {
	if ip == d.ips[0] {
		return d.ips[1]
	}
	return d.ips[0]
}

func (d *Discovery) otherPort(port uint16) uint16 {
	if port == d.ports[0] {
		return d.ports[1]
	}
	return d.ports[0]
}

func (d *Discovery) String() string { return fmt.Sprintf("discovery(%s,%s)", d.loc.Region, d.loc.ISP) }
