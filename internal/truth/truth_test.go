package truth

import (
	"testing"

	"natlab/internal/nat"
)

func site(mapping nat.MappingType, port nat.PortPolicy, blockUDP, blockTCP bool) SiteView {
	return SiteView{
		OuterMapping: mapping,
		OuterFilter:  nat.APDF,
		OuterPort:    port,
		BlockUDP:     blockUDP,
		BlockTCP:     blockTCP,
	}
}

func TestVerdicts(t *testing.T) {
	cases := []struct {
		name string
		a, b SiteView
		want Verdict
	}{
		{"two cones", site(nat.EIM, nat.PortPreserve, false, false), site(nat.EIM, nat.PortPreserve, false, false), DirectUDP},
		{"cone vs symmetric-increment", site(nat.EIM, nat.PortPreserve, false, false), site(nat.APDM, nat.PortIncrement, false, false), DirectUDPPredict},
		{"cone vs symmetric-random", site(nat.EIM, nat.PortPreserve, false, false), site(nat.APDM, nat.PortRandom, false, false), RelayOnly},
		{"double symmetric random", site(nat.APDM, nat.PortRandom, false, false), site(nat.APDM, nat.PortRandom, false, false), RelayOnly},
		{"double symmetric increment", site(nat.APDM, nat.PortIncrement, false, false), site(nat.APDM, nat.PortIncrement, false, false), DirectUDPPredict},
		{"one side blocks UDP", site(nat.EIM, nat.PortPreserve, true, false), site(nat.EIM, nat.PortPreserve, false, false), DirectTCPSimOpen},
		{"both block UDP", site(nat.EIM, nat.PortPreserve, true, false), site(nat.EIM, nat.PortPreserve, true, false), DirectTCPSimOpen},
		{"all transports blocked", site(nat.EIM, nat.PortPreserve, true, true), site(nat.EIM, nat.PortPreserve, true, true), RelayOnly},
		{"UDP blocked vs random symmetric", site(nat.EIM, nat.PortPreserve, true, false), site(nat.APDM, nat.PortRandom, true, false), RelayOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := Decide(c.a, c.b)
			if got != c.want {
				t.Fatalf("Decide = %s, want %s", got, c.want)
			}
		})
	}
}

func TestDirectPossibleFlag(t *testing.T) {
	v, _ := Decide(site(nat.EIM, nat.PortPreserve, false, false), site(nat.APDM, nat.PortRandom, false, false))
	if DirectPossible(v) {
		t.Fatal("random symmetric case must not be directly possible")
	}
	v2, _ := Decide(site(nat.EIM, nat.PortPreserve, false, false), site(nat.EIM, nat.PortPreserve, false, false))
	if !DirectPossible(v2) {
		t.Fatal("two cones must be directly possible")
	}
}
