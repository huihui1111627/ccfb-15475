// Package experiment runs the full NAT-combination matrix under both the
// complete strategy and the naive baseline, cross-checks every cell against
// the analytical verdict and aggregates the acceptance metrics.
package experiment

import (
	"time"

	"natlab/internal/agent"
	"natlab/internal/nat"
	"natlab/internal/scenario"
	"natlab/internal/sim"
	"natlab/internal/truth"
)

// CellResult is one archetype pair at one seed, for one strategy.
type CellResult struct {
	LeftID       string `json:"left_id"`
	RightID      string `json:"right_id"`
	Seed         int64  `json:"seed"`
	Strategy     string `json:"strategy"`
	Success      bool   `json:"success"`
	Via          string `json:"via"` // direct / relay / none
	Protocol     string `json:"protocol"`
	ConnectMS    int64  `json:"connect_ms"`
	RelayBytes   int64  `json:"relay_bytes"`
	DirectBytes  int64  `json:"direct_bytes"`
	PredHits     int    `json:"prediction_hits"`
	FailedChecks int    `json:"failed_checks"`
	Restarts     int    `json:"restarts"`
	// analytical cross-check
	Theory         truth.Verdict `json:"theory"`
	DirectFeasible bool          `json:"direct_feasible"`
	TheoryMatch    bool          `json:"theory_match"`
	Mismatch       string        `json:"mismatch,omitempty"`
	// relay selection detail
	RelayNode   string              `json:"relay_node,omitempty"`
	RelayChoice []agent.RelayChoice `json:"relay_choices,omitempty"`
	// discovery classifications (for the matrix overlay)
	LeftMapping  string `json:"left_mapping"`
	LeftFilter   string `json:"left_filter"`
	RightMapping string `json:"right_mapping"`
	RightFilter  string `json:"right_filter"`
}

// Config controls a matrix run.
type Config struct {
	Seeds     []int64
	RunFor    time.Duration
	RelayCap  int
	Locations [2]sim.Location
}

func DefaultConfig() Config {
	seeds := make([]int64, 4)
	for i := range seeds {
		seeds[i] = int64(11 + i*7)
	}
	return Config{
		Seeds:    seeds,
		RunFor:   15 * time.Second,
		RelayCap: 8,
		Locations: [2]sim.Location{
			{Region: "north", ISP: "isp-a"},
			{Region: "south", ISP: "isp-b"},
		},
	}
}

func newStrategy(name string) agent.Strategy {
	if name == "baseline" {
		return agent.NewBaselineStrategy()
	}
	return agent.NewFullStrategy()
}

// RunCell executes one archetype pair under one strategy/seed.
func RunCell(leftID, rightID, strategyName string, seed int64, cfg Config) CellResult {
	w := scenario.Build(leftID, rightID, cfg.Locations[0], cfg.Locations[1],
		scenario.Options{Seed: seed, RelayCapacity: cfg.RelayCap})
	w.Session(newStrategy(strategyName), newStrategy(strategyName))
	w.Eng.Run(cfg.RunFor)

	left := w.Left().Terminal
	right := w.Right().Terminal
	rep := left.Strategy().Report()
	ev, _ := left.LastEvent()

	viewA := truth.View(leftID, nat.ArchetypeByID(leftID))
	viewB := truth.View(rightID, nat.ArchetypeByID(rightID))
	verdict, _ := truth.Decide(viewA, viewB)
	feasible := truth.DirectPossible(verdict)

	res := CellResult{
		LeftID: leftID, RightID: rightID, Seed: seed, Strategy: strategyName,
		Success: rep.Success, Via: ev.Via, Protocol: ev.Protocol,
		ConnectMS:  rep.ConnectTime.Milliseconds(),
		RelayBytes: rep.RelayBytes, DirectBytes: rep.DirectBytes,
		PredHits: rep.PredictionHits, FailedChecks: rep.FailedChecks,
		Restarts: rep.Restarts, Theory: verdict, DirectFeasible: feasible,
		RelayNode: ev.RelayNode, RelayChoice: rep.RelayChoices,
	}
	if rep.LocalDisc != nil {
		res.LeftMapping, res.LeftFilter = rep.LocalDisc.Mapping.String(), rep.LocalDisc.Filter.String()
	}
	if rep.RemoteDisc != nil && rep.RemoteDisc.OK {
		res.RightMapping, res.RightFilter = rep.RemoteDisc.Mapping.String(), rep.RemoteDisc.Filter.String()
	}
	res.TheoryMatch, res.Mismatch = crossCheck(verdict, feasible, res, right)
	return res
}

// crossCheck compares the measured outcome with the analytical verdict.
func crossCheck(verdict truth.Verdict, feasible bool, res CellResult, right *agent.Terminal) (bool, string) {
	gotDirect := res.Via == "direct"
	switch {
	case feasible && gotDirect:
		return true, ""
	case feasible && !gotDirect:
		return false, "theory says direct possible but strategy used " + res.Via
	case !feasible && gotDirect:
		return false, "theory says relay-only but strategy achieved direct"
	case !feasible && res.Via == "relay":
		return true, ""
	case !feasible && res.Via == "none":
		return false, "relay-only case failed to connect via relay"
	default:
		return false, "unclassified outcome " + res.Via
	}
}

// RunMatrix executes every ordered archetype pair × seed × strategy.
func RunMatrix(cfg Config) []CellResult {
	arches := nat.Archetypes()
	var out []CellResult
	for _, a := range arches {
		for _, b := range arches {
			for _, seed := range cfg.Seeds {
				out = append(out, RunCell(a.ID, b.ID, "full", seed, cfg))
				out = append(out, RunCell(a.ID, b.ID, "baseline", seed, cfg))
			}
		}
	}
	return out
}
