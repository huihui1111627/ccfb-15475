package experiment

import (
	"time"

	"natlab/internal/agent"
	"natlab/internal/nat"
	"natlab/internal/scenario"
	"natlab/internal/sim"
)

func archetype(id string) nat.Archetype { return nat.ArchetypeByID(id) }

// scenarioWorld wraps a recorded world plus its strategy reports.
type scenarioWorld struct {
	World  *scenario.World
	Left   agent.RunReport
	Right  agent.RunReport
	Trace  []sim.TraceEvent
	RunFor time.Duration
}

// traceWorld re-runs one pair with full event recording.
func traceWorld(leftID, rightID, strategyName string, seed int64, cfg Config, runFor time.Duration) (*scenarioWorld, []agent.CheckAttempt, []agent.RelayChoice) {
	w := scenario.Build(leftID, rightID, cfg.Locations[0], cfg.Locations[1],
		scenario.Options{Seed: seed, RelayCapacity: cfg.RelayCap})
	w.Eng.Record = true
	w.Session(newStrategy(strategyName), newStrategy(strategyName))
	w.Eng.Run(runFor)

	left := w.Left().Terminal
	right := w.Right().Terminal
	lr := left.Strategy().Report()
	rr := right.Strategy().Report()

	attempts := append([]agent.CheckAttempt{}, lr.Attempts...)
	attempts = append(attempts, rr.Attempts...)
	choices := append([]agent.RelayChoice{}, lr.RelayChoices...)
	choices = append(choices, rr.RelayChoices...)

	sw := &scenarioWorld{
		World: w, Left: lr, Right: rr,
		Trace: w.Eng.Trace(), RunFor: runFor,
	}
	return sw, attempts, choices
}

// RelayFleet snapshots current relay load/bytes for the dashboard.
func (s *scenarioWorld) RelayFleet() []RelaySnapshot {
	var out []RelaySnapshot
	for _, r := range s.World.Relays {
		out = append(out, RelaySnapshot{
			ID: r.ID(), Region: r.Location().Region, ISP: r.Location().ISP,
			LoadPct: r.LoadPct(), Active: r.ActiveSessions(), Bytes: r.Bytes(),
		})
	}
	return out
}

// TraceWorld is the exported entry used by the web/CLI layer.
func TraceWorld(leftID, rightID, strategy string, seed int64, runFor time.Duration) (*scenarioWorld, []agent.CheckAttempt, []agent.RelayChoice) {
	cfg := DefaultConfig()
	return traceWorld(leftID, rightID, strategy, seed, cfg, runFor)
}

// WorldView exposes the underlying world for the UI.
func (s *scenarioWorld) Underlying() *scenario.World { return s.World }

// TraceEvents returns the recorded event timeline.
func (s *scenarioWorld) TraceEvents() []sim.TraceEvent { return s.Trace }

// LeftReport and RightReport expose the per-side run reports.
func (s *scenarioWorld) LeftReport() agent.RunReport  { return s.Left }
func (s *scenarioWorld) RightReport() agent.RunReport { return s.Right }

// RelayFleetView snapshots relay state for the dashboard.
func (s *scenarioWorld) RelayFleetView() []RelaySnapshot { return s.RelayFleet() }

// TraceMobility runs a pair and forces a network handoff on the left site.
func TraceMobility(leftID, rightID string, seed int64, runFor time.Duration) (*scenarioWorld, []agent.CheckAttempt, []agent.RelayChoice) {
	cfg := DefaultConfig()
	w := scenario.Build(leftID, rightID, cfg.Locations[0], cfg.Locations[1],
		scenario.Options{Seed: seed, RelayCapacity: cfg.RelayCap})
	w.Eng.Record = true
	w.Session(newStrategy("full"), newStrategy("full"))

	// pre-build an alternate network (different archetype + region) and hand
	// the left terminal to it halfway through the run
	gw, lan := w.AddMobilityNetwork(w.Left(), archetype(leftID), sim.Location{Region: "east", ISP: "isp-c"})
	w.AttachMobility(w.Left(), 6*time.Second, gw, lan)

	w.Eng.Run(runFor)
	left := w.Left().Terminal
	right := w.Right().Terminal
	lr, rr := left.Strategy().Report(), right.Strategy().Report()
	attempts := append(append([]agent.CheckAttempt{}, lr.Attempts...), rr.Attempts...)
	sw := &scenarioWorld{World: w, Left: lr, Right: rr, Trace: w.Eng.Trace(), RunFor: runFor}
	return sw, attempts, lr.RelayChoices
}
