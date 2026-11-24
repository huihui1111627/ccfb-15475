// Package truth contains an independent, analytical decision of whether two
// sites can establish a direct connection, derived purely from NAT semantics
// (no simulation). Experiment results are cross-checked against this verdict.
package truth

import (
	"natlab/internal/nat"
)

type Verdict string

const (
	DirectUDP        Verdict = "direct-udp"         // cone-style UDP hole punching works
	DirectUDPPredict Verdict = "direct-udp-predict" // works only with port prediction (increment APDM)
	DirectTCPSimOpen Verdict = "direct-tcp-simopen" // TCP simultaneous open only
	RelayOnly        Verdict = "relay-only"         // no direct path exists
)

// SiteView is the minimal NAT description the verdict needs.
type SiteView struct {
	ID           string
	Chain        []nat.Profile
	OuterMapping nat.MappingType
	OuterFilter  nat.FilterType
	OuterPort    nat.PortPolicy
	BlockUDP     bool
	BlockTCP     bool
}

// View derives the analytical view from an archetype.
func View(id string, a nat.Archetype) SiteView {
	v := SiteView{ID: id, Chain: a.Chain}
	outer := a.Chain[len(a.Chain)-1]
	v.OuterMapping, v.OuterFilter, v.OuterPort = outer.Mapping, outer.Filter, outer.Port
	// an inner NAT also contributes its filter to the effective path
	v.BlockUDP, v.BlockTCP = anyBlocked(a.Chain)
	return v
}

func anyBlocked(chain []nat.Profile) (udp, tcp bool) {
	for _, p := range chain {
		if p.BlockUDP {
			udp = true
		}
		if p.BlockTCP {
			tcp = true
		}
	}
	return
}

// Decide returns the theoretical verdict and a human-readable reason.
// The decision follows the port-predictability of the outermost mapping and
// models both UDP hole punching and TCP simultaneous open realistically.
func Decide(a, b SiteView) (Verdict, string) {
	// protocol-blocking networks
	eitherSym := eitherSymmetric(a, b)
	// a side is TCP-traversable if it is not symmetric, or its symmetric NAT
	// uses predictable external ports (increment or preserved)
	tcpOK := func(v SiteView) bool {
		return v.OuterMapping != nat.APDM ||
			v.OuterPort == nat.PortIncrement || v.OuterPort == nat.PortPreserve
	}
	switch {
	case a.BlockUDP && b.BlockUDP:
		if !a.BlockTCP && !b.BlockTCP && (!eitherSym || (tcpOK(a) && tcpOK(b))) {
			return DirectTCPSimOpen, "UDP blocked both sides; TCP simultaneous open remains"
		}
		return RelayOnly, "all common transports blocked or symmetric: relay mandatory"
	case a.BlockUDP || b.BlockUDP:
		if !a.BlockTCP && !b.BlockTCP && (!eitherSym || (tcpOK(a) && tcpOK(b))) {
			return DirectTCPSimOpen, "one side blocks UDP; TCP simultaneous open over predictable NATs"
		}
		return RelayOnly, "UDP blocked and TCP cannot traverse the unpredictable symmetric device"
	}

	// both sides UDP-reachable from here on.
	aSym := a.OuterMapping == nat.APDM
	bSym := b.OuterMapping == nat.APDM

	switch {
	case !aSym && !bSym:
		// EIM/ADM on both: the reflexive tuple is destination-independent,
		// simultaneous opens satisfy ADF/APDF filters on both sides.
		return DirectUDP, "endpoint-independent mappings: classic UDP hole punching"
	case aSym && bSym:
		// Both ends symmetric. Direct connectivity is possible only when BOTH
		// devices keep a predictable external port: either a deterministic
		// increment or preserved stable per-socket ports. Randomized allocation
		// on either side makes the peer's target unknowable.
		predictable := func(pp nat.PortPolicy) bool {
			return pp == nat.PortIncrement || pp == nat.PortPreserve
		}
		if predictable(a.OuterPort) && predictable(b.OuterPort) {
			return DirectUDPPredict, "double symmetric with predictable ports"
		}
		return RelayOnly, "double symmetric with unpredictable allocation: relay required"
	default:
		// one symmetric, one cone. The cone side must reach the symmetric
		// side's per-destination mapping; feasible when its external port is
		// predictable (deterministic increment or preserved local port).
		sym := a
		if !aSym {
			sym = b
		}
		if sym.OuterPort == nat.PortIncrement || sym.OuterPort == nat.PortPreserve {
			return DirectUDPPredict, "one symmetric NAT with predictable external ports"
		}
		return RelayOnly, "one symmetric NAT randomizes ports: peer cannot target a valid mapping"
	}
}

func eitherSymmetric(a, b SiteView) bool {
	return a.OuterMapping == nat.APDM || b.OuterMapping == nat.APDM
}

// DirectPossible reports whether any direct path exists (UDP or TCP).
func DirectPossible(v Verdict) bool {
	return v != RelayOnly
}

// NeedsPrediction reports whether the direct path requires port prediction.
func NeedsPrediction(v Verdict) bool { return v == DirectUDPPredict }
