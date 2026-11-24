package scenario

import (
	"testing"
	"time"

	"natlab/internal/agent"
	"natlab/internal/nat"
	"natlab/internal/sim"
	"natlab/internal/truth"
)

func TestConeToConeDirect(t *testing.T) {
	w := Build("fullcone", "portrestricted",
		sim.Location{Region: "north", ISP: "isp-a"},
		sim.Location{Region: "south", ISP: "isp-b"},
		Options{Seed: 7, RelayCapacity: 8})
	w.Session(agent.NewFullStrategy(), agent.NewFullStrategy())
	w.Eng.Run(12 * time.Second)
	ev, ok := w.Left().Terminal.LastEvent()
	if !ok {
		t.Fatal("no connection event")
	}
	if ev.Via != "direct" {
		t.Fatalf("expected direct, got %s (%s)", ev.Via, ev.Path)
	}
}

func TestDoubleSymmetricRelay(t *testing.T) {
	w := Build("symmetric-rand", "symmetric-rand",
		sim.Location{Region: "north", ISP: "isp-a"},
		sim.Location{Region: "north", ISP: "isp-a"},
		Options{Seed: 9})
	w.Session(agent.NewFullStrategy(), agent.NewFullStrategy())
	w.Eng.Run(15 * time.Second)
	ev, _ := w.Left().Terminal.LastEvent()
	if ev.Via != "relay" {
		t.Fatalf("expected relay for double random symmetric, got %s", ev.Via)
	}
}

func TestNestedTraversal(t *testing.T) {
	w := Build("nested-cone-sym", "fullcone",
		sim.Location{Region: "north", ISP: "isp-a"},
		sim.Location{Region: "south", ISP: "isp-b"},
		Options{Seed: 13})
	w.Session(agent.NewFullStrategy(), agent.NewFullStrategy())
	w.Eng.Run(15 * time.Second)
	ev, _ := w.Left().Terminal.LastEvent()
	if ev.Via != "direct" {
		t.Fatalf("expected direct through double NAT, got %s (%s)", ev.Via, ev.Path)
	}
}

func TestTruthMatrix(t *testing.T) {
	a := truth.View("a", nat.ArchetypeByID("symmetric-inc"))
	b := truth.View("b", nat.ArchetypeByID("fullcone"))
	if v, _ := truth.Decide(a, b); v != truth.DirectUDPPredict {
		t.Fatalf("expected predict verdict, got %s", v)
	}
	c := truth.View("c", nat.ArchetypeByID("symmetric-rand"))
	if v, _ := truth.Decide(c, c); v != truth.RelayOnly {
		t.Fatalf("expected relay-only, got %s", v)
	}
	d := truth.View("d", nat.ArchetypeByID("udp-blocked"))
	if v, _ := truth.Decide(d, b); v != truth.DirectTCPSimOpen {
		t.Fatalf("expected TCP fallback verdict, got %s", v)
	}
}
