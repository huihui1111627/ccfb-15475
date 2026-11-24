package nat

import (
	"testing"
	"time"

	"natlab/internal/sim"
)

// helper engine with an inner host chained below the device under test
type stubNode struct{ id string }

func (s stubNode) ID() string                            { return s.id }
func (s stubNode) Location() sim.Location                { return sim.Location{} }
func (s stubNode) OnPacket(e *sim.Engine, p *sim.Packet) {}

func newTestDevice(t *testing.T, prof Profile) (*Device, *sim.Engine) {
	t.Helper()
	eng := sim.NewEngine(1, sim.DefaultLinks())
	inner := stubNode{id: "inner-host"}
	eng.RegisterNode(inner)
	eng.RegisterIP("192.168.0.5", inner)
	d := New("nat", "203.0.1.1", sim.Location{}, prof, eng)
	eng.RegisterNode(d)
	eng.SetUpstream(inner, d)
	return d, eng
}

// sendOut emits an outbound packet from the inner host through the NAT chain
// and advances the virtual clock enough for the delayed delivery to complete.
func sendOut(eng *sim.Engine, src, dst sim.Endpoint) {
	eng.Emit(stubNode{id: "inner-host"}, src, dst, &sim.KeepAlive{}, 100)
	eng.Run(50 * time.Millisecond)
}

func TestEIMReusesMappingAcrossDestinations(t *testing.T) {
	d, eng := newTestDevice(t, Profile{Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: time.Minute})
	src := sim.Endpoint{IP: "192.168.0.5", Port: 5000, Proto: sim.UDP}
	sendOut(eng, src, sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.UDP})
	sendOut(eng, src, sim.Endpoint{IP: "1.1.1.1", Port: 200, Proto: sim.UDP})
	if len(d.entries) != 1 {
		t.Fatalf("EIM should keep one mapping per inner socket, got %d", len(d.entries))
	}
}

func TestAPDMAllocatesPerDestinationPort(t *testing.T) {
	d, eng := newTestDevice(t, Profile{Mapping: APDM, Filter: APDF, Port: PortIncrement, MappingTimeout: time.Minute})
	src := sim.Endpoint{IP: "192.168.0.5", Port: 5000, Proto: sim.UDP}
	sendOut(eng, src, sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.UDP})
	sendOut(eng, src, sim.Endpoint{IP: "8.8.8.8", Port: 200, Proto: sim.UDP})
	if len(d.entries) != 2 {
		t.Fatalf("APDM must allocate a fresh mapping per destination port, got %d", len(d.entries))
	}
}

func TestAPDFFiltersUnknownPeer(t *testing.T) {
	d, eng := newTestDevice(t, Profile{Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: time.Minute})
	inner := sim.Endpoint{IP: "192.168.0.5", Port: 5000, Proto: sim.UDP}
	// open a mapping toward 8.8.8.8:100
	sendOut(eng, inner, sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.UDP})
	// inbound from a never-contacted sender must be rejected by the filter
	inbound := &sim.Packet{
		Src: sim.Endpoint{IP: "9.9.9.9", Port: 7777, Proto: sim.UDP},
		Dst: sim.Endpoint{IP: d.pubIP, Port: 5000, Proto: sim.UDP}, Msg: &sim.KeepAlive{},
	}
	en := d.findInbound(inbound)
	if en == nil {
		t.Fatal("expected to locate the port-owning mapping")
	}
	if d.filterAllows(en, inbound) {
		t.Fatal("APDF must reject traffic from an unknown peer endpoint")
	}
}

func TestProtocolBlocking(t *testing.T) {
	d, eng := newTestDevice(t, Profile{Mapping: EIM, Filter: APDF, Port: PortPreserve, BlockUDP: true, MappingTimeout: time.Minute})
	src := sim.Endpoint{IP: "192.168.0.5", Port: 5000}
	sendOut(eng, sim.Endpoint{Node: "inner-host", IP: src.IP, Port: src.Port, Proto: sim.UDP},
		sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.UDP})
	if len(d.entries) != 0 {
		t.Fatal("blocked UDP must not create a mapping")
	}
	sendOut(eng, sim.Endpoint{Node: "inner-host", IP: src.IP, Port: src.Port, Proto: sim.TCP},
		sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.TCP})
	if len(d.entries) != 1 {
		t.Fatal("TCP should still pass when only UDP is blocked")
	}
}

func TestMappingTimeoutExpiry(t *testing.T) {
	d, eng := newTestDevice(t, Profile{Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: 100 * time.Millisecond})
	src := sim.Endpoint{IP: "192.168.0.5", Port: 5000, Proto: sim.UDP}
	sendOut(eng, src, sim.Endpoint{IP: "8.8.8.8", Port: 100, Proto: sim.UDP})
	if len(d.entries) != 1 {
		t.Fatal("expected one mapping after outbound")
	}
	eng.Run(1500 * time.Millisecond)
	if len(d.entries) != 0 {
		t.Fatalf("expired mapping should be reaped, got %d entries", len(d.entries))
	}
}
