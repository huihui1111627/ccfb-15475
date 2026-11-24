package experiment

import (
	"sort"
	"time"

	"natlab/internal/agent"
)

// Aggregate is the rolled-up acceptance metric set for one strategy.
type Aggregate struct {
	Strategy        string  `json:"strategy"`
	Runs            int     `json:"runs"`
	Successes       int     `json:"successes"`
	Direct          int     `json:"direct"`
	Relayed         int     `json:"relayed"`
	Failed          int     `json:"failed"`
	DirectRate      float64 `json:"direct_rate"`
	SuccessRate     float64 `json:"success_rate"`
	RelayTrafficPct float64 `json:"relay_traffic_pct"`
	AvgConnectMS    float64 `json:"avg_connect_ms"`
	AvgDirectMS     float64 `json:"avg_direct_ms"`
	AvgRelayMS      float64 `json:"avg_relay_ms"`
	AvgRelayRTTMS   float64 `json:"avg_relay_rtt_ms"`
	TheoryMatches   int     `json:"theory_matches"`
	TheoryTotal     int     `json:"theory_total"`
	TheoryMatchRate float64 `json:"theory_match_rate"`
	PredictionHits  int     `json:"prediction_hits"`
}

// AggregateAll partitions results by strategy and summarizes each.
func AggregateAll(results []CellResult) map[string]*Aggregate {
	aggs := map[string]*Aggregate{}
	for _, r := range results {
		a := aggs[r.Strategy]
		if a == nil {
			a = &Aggregate{Strategy: r.Strategy}
			aggs[r.Strategy] = a
		}
		a.Runs++
		if r.Success {
			a.Successes++
		}
		switch r.Via {
		case "direct":
			a.Direct++
			a.AvgDirectMS += float64(r.ConnectMS)
		case "relay":
			a.Relayed++
			a.AvgRelayMS += float64(r.ConnectMS)
			if len(r.RelayChoice) > 0 {
				for _, rc := range r.RelayChoice {
					if rc.Chosen {
						a.AvgRelayRTTMS += float64(rc.ProbeRTT.Milliseconds())
					}
				}
			}
		default:
			a.Failed++
		}
		a.AvgConnectMS += float64(r.ConnectMS)
		a.RelayTrafficPct += float64(r.RelayBytes)
		a.TheoryTotal++
		if r.TheoryMatch {
			a.TheoryMatches++
		}
		a.PredictionHits += r.PredHits
	}
	for _, a := range aggs {
		n := float64(a.Runs)
		a.DirectRate = pct(a.Direct, a.Runs)
		a.SuccessRate = pct(a.Successes, a.Runs)
		totalBytes := 0.0
		// recompute relay traffic share from bytes recorded on results
		for _, r := range results {
			if r.Strategy == a.Strategy {
				totalBytes += float64(r.RelayBytes + r.DirectBytes)
			}
		}
		if totalBytes > 0 {
			a.RelayTrafficPct = a.RelayTrafficPct / totalBytes * 100
		}
		a.AvgConnectMS /= n
		if a.Direct > 0 {
			a.AvgDirectMS /= float64(a.Direct)
		}
		if a.Relayed > 0 {
			a.AvgRelayMS /= float64(a.Relayed)
			a.AvgRelayRTTMS /= float64(a.Relayed)
		}
		a.TheoryMatchRate = pct(a.TheoryMatches, a.TheoryTotal)
	}
	return aggs
}

func pct(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) * 100 / float64(den)
}

// MatrixCell aggregates one archetype pair across seeds for the UI heat map.
type MatrixCell struct {
	LeftID         string   `json:"left_id"`
	RightID        string   `json:"right_id"`
	DirectRate     float64  `json:"direct_rate"`
	RelayRate      float64  `json:"relay_rate"`
	FailRate       float64  `json:"fail_rate"`
	Theory         string   `json:"theory"`
	DirectFeasible bool     `json:"direct_feasible"`
	MatchRate      float64  `json:"theory_match_rate"`
	AvgConnectMS   float64  `json:"avg_connect_ms"`
	Verdicts       []string `json:"verdicts"`
}

// BuildMatrix collapses per-seed results into per-pair cells for a strategy.
func BuildMatrix(results []CellResult, strategy string) []MatrixCell {
	type key struct{ l, r string }
	groups := map[key][]CellResult{}
	var order []key
	for _, r := range results {
		if r.Strategy != strategy {
			continue
		}
		k := key{r.LeftID, r.RightID}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	var cells []MatrixCell
	for _, k := range order {
		grp := groups[k]
		var c MatrixCell
		c.LeftID, c.RightID = k.l, k.r
		direct, relay, fail, match := 0, 0, 0, 0
		var connSum float64
		seenVerdict := map[string]bool{}
		for _, r := range grp {
			switch r.Via {
			case "direct":
				direct++
			case "relay":
				relay++
			default:
				fail++
			}
			if r.TheoryMatch {
				match++
			}
			connSum += float64(r.ConnectMS)
			if !seenVerdict[string(r.Theory)] {
				seenVerdict[string(r.Theory)] = true
				c.Verdicts = append(c.Verdicts, string(r.Theory))
			}
			c.Theory, c.DirectFeasible = string(r.Theory), r.DirectFeasible
		}
		n := len(grp)
		c.DirectRate = pct(direct, n)
		c.RelayRate = pct(relay, n)
		c.FailRate = pct(fail, n)
		c.MatchRate = pct(match, n)
		c.AvgConnectMS = connSum / float64(n)
		cells = append(cells, c)
	}
	sort.SliceStable(cells, func(i, j int) bool {
		if cells[i].LeftID != cells[j].LeftID {
			return cells[i].LeftID < cells[j].LeftID
		}
		return cells[i].RightID < cells[j].RightID
	})
	return cells
}

// RelaySnapshot is a point-in-time view of relay fleet state for the UI.
type RelaySnapshot struct {
	ID      string `json:"id"`
	Region  string `json:"region"`
	ISP     string `json:"isp"`
	LoadPct int    `json:"load_pct"`
	Active  int    `json:"active"`
	Bytes   int64  `json:"bytes"`
}

// TraceRun re-runs a single pair with event recording for the probe-timeline view.
func TraceRun(leftID, rightID, strategy string, seed int64, cfg Config, runFor time.Duration) (*scenarioWorld, []agent.CheckAttempt, []agent.RelayChoice) {
	// implemented in trace.go to keep this file focused on aggregation
	return traceWorld(leftID, rightID, strategy, seed, cfg, runFor)
}
