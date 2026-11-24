package sim

import (
	"math/rand"
	"time"
)

// Regions and ISPs used across the emulated world.
var Regions = []string{"north", "south", "east", "west"}
var ISPs = []string{"isp-a", "isp-b", "isp-c"}

// one-way backbone latency (ms) between regions; symmetric matrix.
var regionOneWayMS = map[string]map[string]int{
	"north": {"north": 4, "south": 28, "east": 18, "west": 22},
	"south": {"north": 28, "south": 4, "east": 24, "west": 16},
	"east":  {"north": 18, "south": 24, "east": 4, "west": 30},
	"west":  {"north": 22, "south": 16, "east": 30, "west": 4},
}

// LinkModel computes per-link delay and loss from node locations.
type LinkModel struct {
	CrossISPMs   int // extra one-way latency when the two nodes use different ISPs
	AccessRTTMs  int // typical last-mile RTT contribution base (half used each way)
	JitterMS     int // uniform jitter magnitude each direction
	LossPerMille int // datagram loss rate on non-signaling links
}

func DefaultLinks() *LinkModel {
	return &LinkModel{CrossISPMs: 9, AccessRTTMs: 8, JitterMS: 2, LossPerMille: 3}
}

// Plan returns the one-way delay and whether the packet is lost.
func (m *LinkModel) Plan(rng *rand.Rand, from, to Node, p *Packet) (time.Duration, bool) {
	lf, lt := from.Location(), to.Location()
	ms := regionOneWayMS[lf.Region][lt.Region]
	if lf.ISP != lt.ISP {
		ms += m.CrossISPMs
	}
	// last-mile contribution of each access endpoint
	if an, ok := from.(AccessNode); ok {
		ms += int(an.AccessRTT().Milliseconds() / 2)
	}
	if an, ok := to.(AccessNode); ok {
		ms += int(an.AccessRTT().Milliseconds() / 2)
	}
	if m.JitterMS > 0 {
		ms += rng.Intn(2*m.JitterMS+1) - m.JitterMS
		if ms < 1 {
			ms = 1
		}
	}
	// signaling and relay control traffic are carried over a reliable channel
	lost := false
	if m.LossPerMille > 0 {
		switch p.Msg.(type) {
		case *Signal, *RelayAlloc, *RelayAllocAck, *RelayBind:
			lost = false
		default:
			lost = rng.Intn(1000) < m.LossPerMille
		}
	}
	return time.Duration(ms) * time.Millisecond, lost
}
