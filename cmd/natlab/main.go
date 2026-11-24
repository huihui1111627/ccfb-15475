// Command natlab runs the NAT-traversal simulation suite and writes results
// for the embedded dashboard.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"natlab/internal/experiment"
	"natlab/internal/nat"
	"natlab/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", ":8080", "listen address")
		data := fs.String("data", "webdata", "directory with JSON artifacts")
		_ = fs.Parse(os.Args[2:])
		srv := web.NewServer(*data)
		fmt.Println("natlab dashboard on http://localhost" + *addr + " (data: " + *data + ")")
		fatal(srv.ListenAndServe(*addr))
		return
	}
	runMatrixCLI()
}

func archetypeIDs() []string {
	var ids []string
	for _, a := range nat.Archetypes() {
		ids = append(ids, a.ID)
	}
	return ids
}

func runMatrixCLI() {
	var (
		outDir   = flag.String("out", "webdata", "output directory for JSON artifacts")
		seeds    = flag.Int("seeds", 4, "random seeds per archetype pair")
		runSecs  = flag.Int("duration", 15, "simulated seconds per run")
		traceA   = flag.String("trace-a", "symmetric-inc", "left archetype for the probe trace")
		traceB   = flag.String("trace-b", "symmetric-inc", "right archetype for the probe trace")
		mobility = flag.Bool("mobility", true, "also run a network-handoff scenario")
	)
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}
	cfg := experiment.DefaultConfig()
	cfg.Seeds = make([]int64, *seeds)
	for i := range cfg.Seeds {
		cfg.Seeds[i] = int64(11 + i*7)
	}
	cfg.RunFor = time.Duration(*runSecs) * time.Second

	fmt.Printf("running matrix: %d archetypes^2 x %d seeds x 2 strategies ...\n",
		len(archetypeIDs()), *seeds)
	results := experiment.RunMatrix(cfg)
	writeJSON(filepath.Join(*outDir, "results.json"), results)

	aggs := experiment.AggregateAll(results)
	writeJSON(filepath.Join(*outDir, "aggregate.json"), aggs)
	writeJSON(filepath.Join(*outDir, "matrix-full.json"), experiment.BuildMatrix(results, "full"))
	writeJSON(filepath.Join(*outDir, "matrix-baseline.json"), experiment.BuildMatrix(results, "baseline"))

	// detailed single-run trace for the connection timeline view
	sw, attempts, choices := experiment.TraceWorld(*traceA, *traceB, "full", cfg.Seeds[0], 12*time.Second)
	writeJSON(filepath.Join(*outDir, "trace.json"), map[string]any{
		"left": *traceA, "right": *traceB, "strategy": "full", "seed": cfg.Seeds[0],
		"events":        sw.TraceEvents(),
		"attempts":      attempts,
		"relay_choices": choices,
		"left_report":   sw.LeftReport(),
		"right_report":  sw.RightReport(),
		"relay_fleet":   sw.RelayFleetView(),
	})

	// baseline trace of the same pair, for side-by-side comparison
	swB, attB, _ := experiment.TraceWorld(*traceA, *traceB, "baseline", cfg.Seeds[0], 12*time.Second)
	writeJSON(filepath.Join(*outDir, "trace-baseline.json"), map[string]any{
		"left": *traceA, "right": *traceB, "strategy": "baseline",
		"events":       swB.TraceEvents(),
		"attempts":     attB,
		"left_report":  swB.LeftReport(),
		"right_report": swB.RightReport(),
	})

	if *mobility {
		runMobility(*outDir, cfg)
	}

	printSummary(aggs)
	fmt.Println("artifacts written to", *outDir)
}

func runMobility(outDir string, cfg experiment.Config) {
	sw, attempts, choices := experiment.TraceMobility("portrestricted", "fullcone", cfg.Seeds[0], 18*time.Second)
	writeJSON(filepath.Join(outDir, "mobility.json"), map[string]any{
		"events":        sw.TraceEvents(),
		"attempts":      attempts,
		"relay_choices": choices,
		"left_report":   sw.LeftReport(),
		"right_report":  sw.RightReport(),
		"relay_fleet":   sw.RelayFleetView(),
	})
}

func printSummary(aggs map[string]*experiment.Aggregate) {
	for _, name := range []string{"full", "baseline"} {
		a := aggs[name]
		if a == nil {
			continue
		}
		fmt.Printf("\n=== %s ===\n", name)
		fmt.Printf("runs=%d success=%.1f%% direct=%.1f%% relayed=%d failed=%d\n",
			a.Runs, a.SuccessRate, a.DirectRate, a.Relayed, a.Failed)
		fmt.Printf("avg connect=%dms (direct %dms / relay %dms) relay traffic=%.2f%%\n",
			int(a.AvgConnectMS), int(a.AvgDirectMS), int(a.AvgRelayMS), a.RelayTrafficPct)
		fmt.Printf("theory match=%.1f%% (%d/%d) prediction hits=%d relay probe RTT=%dms\n",
			a.TheoryMatchRate, a.TheoryMatches, a.TheoryTotal, a.PredictionHits, int(a.AvgRelayRTTMS))
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
