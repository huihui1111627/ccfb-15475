package agent

import "time"

// ConnectedEvent summarizes the winning path.
type ConnectedEvent struct {
	Via         string // direct / relay
	Path        string // candidate-pair description
	Protocol    string
	ConnectTime time.Duration
	RelayNode   string
	RestartID   uint32
	Local       string
	Remote      string
}

// CheckAttempt records one connectivity-check probe.
type CheckAttempt struct {
	T         time.Duration `json:"t_ms"`
	Local     string        `json:"local"`
	Remote    string        `json:"remote"`
	Proto     string        `json:"proto"`
	Kind      string        `json:"kind"` // candidate type pair, e.g. srflx-srflx
	Predicted bool          `json:"predicted"`
	Result    string        `json:"result"` // sent / success / filtered / timeout
	RTT       time.Duration `json:"rtt_ms"`
}

// RelayChoice records why a relay was picked.
type RelayChoice struct {
	T        time.Duration `json:"t_ms"`
	Relay    string        `json:"relay"`
	Region   string        `json:"region"`
	ISP      string        `json:"isp"`
	LoadPct  int           `json:"load_pct"`
	Score    float64       `json:"score"`
	ProbeRTT time.Duration `json:"probe_rtt_ms"`
	Chosen   bool          `json:"chosen"`
	Reason   string        `json:"reason"`
}

// RunReport holds everything measured during one connection attempt.
type RunReport struct {
	Strategy       string
	Success        bool
	Via            string // direct / relay / none
	ConnectTime    time.Duration
	Protocol       string
	LocalDisc      *DiscoveryResult
	RemoteDisc     *DiscoveryResult
	Attempts       []CheckAttempt
	RelayChoices   []RelayChoice
	RelayBytes     int64
	DirectBytes    int64
	Restarts       int
	FailedChecks   int
	PredictionHits int
	WinningPath    string
	FinishedAt     time.Duration
	// mobility
	Reconnected   bool
	ReconnectTime time.Duration
}

func (r *RunReport) mark(ev CheckAttempt) {
	r.Attempts = append(r.Attempts, ev)
}
