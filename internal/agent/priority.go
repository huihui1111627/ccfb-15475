package agent

import (
	"natlab/internal/nat"
	"natlab/internal/sim"
)

// ICE-style component preference: UDP beats TCP, host beats srflx beats relay.
func candTypePref(t string) uint32 {
	switch t {
	case "host":
		return 126
	case "srflx":
		return 100
	case "relay":
		return 0
	}
	return 50
}

func protoPref(p sim.Protocol) uint32 {
	if p == sim.UDP {
		return 2
	}
	return 1
}

// CandidatePriority mirrors RFC 8445 priority arithmetic (24-bit local value).
func CandidatePriority(t string, p sim.Protocol) uint32 {
	return candTypePref(t)<<24 | protoPref(p)<<8 | 255
}

// PairPriority combines both sides' priorities, controlling check order.
func PairPriority(local, remote sim.Cand) uint64 {
	g, d := local.Priority, remote.Priority
	if g < d {
		g, d = d, g
	}
	return uint64(g)<<32 | uint64(d)
}

// PredictPorts produces candidate srflx ports for the peer's APDM NAT using
// the observed increment delta and a window wide enough to absorb the ports
// consumed by the peer's own simultaneous probes.
func PredictPorts(last uint16, delta int, policy nat.PortPolicy) []uint16 {
	switch policy {
	case nat.PortIncrement:
		if delta <= 0 {
			delta = 1
		}
		out := make([]uint16, 0, 16)
		// the peer will allocate several fresh mappings while punching; cover
		// the next ~12 increments rather than only the immediate next port
		for k := 1; k <= 12; k++ {
			out = append(out, last+uint16(delta*k))
		}
		// tight uncertainty window around the first few predictions
		base := last + uint16(delta)
		for _, off := range []int{-3, -2, -1, 1, 2, 3} {
			out = append(out, base+uint16(off))
		}
		return dedupPorts(out)
	case nat.PortRandom:
		// cannot predict; return nothing so the caller falls back to relay
		return nil
	default:
		return []uint16{last} // preserve: external port stays stable
	}
}

func dedupPorts(in []uint16) []uint16 {
	seen := map[uint16]bool{}
	out := in[:0]
	for _, p := range in {
		if p < 1024 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
