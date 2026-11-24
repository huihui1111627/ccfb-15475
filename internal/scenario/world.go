// Package scenario assembles complete emulated worlds: terminals, nested NAT
// chains, discovery/signaling/relay servers and the links between them.
package scenario

import (
	"fmt"
	"math/rand"
	"time"

	"natlab/internal/agent"
	"natlab/internal/nat"
	"natlab/internal/server"
	"natlab/internal/sim"
)

// Site describes one endpoint's network position.
type Site struct {
	ID       string // archetype id
	Label    string // "A" or "B", unique within a world
	Loc      sim.Location
	Arche    nat.Archetype
	AccessRT time.Duration
	LANIP    string
	NATs     []*nat.Device // outer-most last
	Terminal *agent.Terminal
}

// World is one fully wired simulation.
type World struct {
	Eng    *sim.Engine
	Sig    *server.Signaling
	Discs  []*server.Discovery
	Relays []*server.Relay
	Sites  []*Site // ordered [A, B]; a slice because archetype ids can repeat
	pool   *ipPool
}

// Left and Right return the two endpoints.
func (w *World) Left() *Site  { return w.Sites[0] }
func (w *World) Right() *Site { return w.Sites[1] }

// Options controls world construction.
type Options struct {
	Seed          int64
	RelaysPerLoc  int
	RelayCapacity int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{Seed: 1, RelaysPerLoc: 1, RelayCapacity: 8}
}

type ipPool struct {
	pub  uint32
	priv uint32
	tag  uint32
}

func newIPPool() *ipPool { return &ipPool{pub: 203 << 24, priv: 192<<24 | 168<<16} }

func (p *ipPool) uniqueTag() string {
	p.tag++
	return fmt.Sprintf("n%04d", p.tag)
}

func (p *ipPool) public() string {
	p.pub++
	return ipv4(p.pub)
}

func (p *ipPool) private() string {
	p.priv++
	return ipv4(p.priv)
}

func ipv4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Build constructs a world with the two named archetypes at chosen locations.
// The map iteration order is randomized, so sites are built in a fixed order.
func Build(leftID, rightID string, locA, locB sim.Location, opts Options) *World {
	// fill defaults for any zero-valued option so partial Options still work
	if opts.RelaysPerLoc <= 0 {
		opts.RelaysPerLoc = 1
	}
	if opts.RelayCapacity <= 0 {
		opts.RelayCapacity = 8
	}
	eng := sim.NewEngine(opts.Seed, sim.DefaultLinks())
	pool := newIPPool()
	w := &World{Eng: eng, pool: pool}

	// signaling service (carrier-grade shared address)
	w.Sig = server.NewSignaling("signal", sim.Location{Region: "north", ISP: "isp-a"}, eng)
	eng.RegisterNode(w.Sig)

	// discovery servers: two locations, each with two public IPs/ports
	for i, loc := range []sim.Location{
		{Region: "north", ISP: "isp-a"},
		{Region: "south", ISP: "isp-b"},
	} {
		ip1, ip2 := pool.public(), pool.public()
		d := server.NewDiscovery(fmt.Sprintf("disc-%d", i), loc, ip1, ip2, 3478, 3479, eng)
		eng.RegisterNode(d)
		w.Discs = append(w.Discs, d)
	}

	// one relay per region/ISP combination, capacity-limited
	for _, reg := range sim.Regions {
		region := reg
		for _, ispName := range sim.ISPs {
			isp := ispName
			for k := 0; k < opts.RelaysPerLoc; k++ {
				r := server.NewRelay(
					fmt.Sprintf("relay-%s-%s-%d", region, isp, k),
					sim.Location{Region: region, ISP: isp},
					pool.public(), opts.RelayCapacity, eng)
				eng.RegisterNode(r)
				w.Relays = append(w.Relays, r)
			}
		}
	}

	// shuffle relay order using a DEDICATED random source so the fleet's
	// arbitrary registration order never perturbs the simulation's main RNG
	// stream (which must stay deterministic per seed).
	shuffleRng := rand.New(rand.NewSource(opts.Seed + 99991))
	shuffleRng.Shuffle(len(w.Relays), func(i, j int) {
		w.Relays[i], w.Relays[j] = w.Relays[j], w.Relays[i]
	})

	w.Sites = append(w.Sites,
		buildSite(eng, pool, "A", leftID, nat.ArchetypeByID(leftID), locA),
		buildSite(eng, pool, "B", rightID, nat.ArchetypeByID(rightID), locB),
	)

	for _, st := range w.Sites {
		st.Terminal.BindServices(w.Sig, w.Discs, w.Relays)
	}
	return w
}

func buildSite(eng *sim.Engine, pool *ipPool, label, archeID string, arche nat.Archetype, loc sim.Location) *Site {
	lanIP := pool.private()
	var nats []*nat.Device
	var prevID string
	for i, prof := range arche.Chain {
		// globally unique device id: two sites may use the same archetype,
		// and the engine's routing tables are keyed by node id
		devName := fmt.Sprintf("%s-%s-%d-%s", label, archeID, i, pool.uniqueTag())
		prof.Name = devName
		dev := nat.New(devName, pool.public(), loc, prof, eng)
		eng.RegisterNode(dev)
		if i > 0 {
			// an inner NAT needs a private address its outer neighbor can route to
			dev.AttachInnerIP(pool.private(), eng)
			eng.SetUpstream(nats[i-1], dev)
		}
		nats = append(nats, dev)
		if i == 0 {
			prevID = dev.ID()
		}
	}
	hostName := label + "-host-" + pool.uniqueTag()
	term := agent.NewTerminal(hostName, loc, time.Duration(6+eng.Rng.Intn(8))*time.Millisecond,
		lanIP, prevID, eng)
	term.SetSignalName(label + "-host") // stable logical name for signaling lookup
	eng.RegisterNode(term)
	if len(nats) > 0 {
		eng.SetUpstream(term, nats[0])
	}
	return &Site{
		ID: archeID, Label: label, Loc: loc, Arche: arche,
		AccessRT: term.AccessRTT(), LANIP: lanIP, NATs: nats, Terminal: term,
	}
}

// AddMobilityNetwork pre-builds an alternate NAT chain a terminal can hand off to.
// It shares the world's address space so all public IPs stay globally unique.
func (w *World) AddMobilityNetwork(site *Site, arche nat.Archetype, loc sim.Location) (gatewayID, lanIP string) {
	st := buildSite(w.Eng, w.pool, site.Label+"-mobile", arche.ID, arche, loc)
	for _, d := range st.NATs {
		w.Eng.RegisterNode(d)
	}
	if len(st.NATs) > 0 {
		gatewayID = st.NATs[0].ID()
	}
	return gatewayID, st.LANIP
}

// AttachMobility schedules a Wi-Fi/cellular-style handoff for one site.
func (w *World) AttachMobility(site *Site, at time.Duration, gatewayID, newLAN string) {
	site.Terminal.SetMobility(at, agent.MobilityTarget{NewLANIP: newLAN, NewGateway: gatewayID})
}

// Session wires two strategies to the two terminals and starts the session.
func (w *World) Session(a, b agent.Strategy) {
	sA := w.Left().Terminal
	sB := w.Right().Terminal
	// bind both strategies before any signaling flows, so the responder's
	// offer callback is registered when the message arrives
	sA.SetStrategy(a)
	sB.SetStrategy(b)
	a.Begin(sA, "sess-A-B", sB.SignalName())
	// responder is driven by the incoming offer signal
}
