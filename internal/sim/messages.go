package sim

// MsgName returns a compact display name for a message.
func MsgName(m Msg) string {
	if m == nil {
		return "raw"
	}
	switch m.(type) {
	case *DiscReq:
		return "DiscReq"
	case *DiscResp:
		return "DiscResp"
	case *FilterProbe:
		return "FilterProbe"
	case *Signal:
		return "Signal." + m.(*Signal).What
	case *RelayAlloc:
		return "RelayAlloc"
	case *RelayAllocAck:
		return "RelayAllocAck"
	case *RelayBind:
		return "RelayBind"
	case *RelayData:
		return "RelayData"
	case *ConnCheck:
		return "ConnCheck"
	case *ConnCheckAck:
		return "ConnCheckAck"
	case *KeepAlive:
		return "KeepAlive"
	case *AppData:
		return "AppData"
	default:
		return "Msg"
	}
}

// ---------- discovery protocol ----------

type DiscReq struct {
	FlowID     uint32 `json:"flow_id"`
	ChangeIP   bool   `json:"change_ip"`
	ChangePort bool   `json:"change_port"`
	ExpectIP   string `json:"expect_ip,omitempty"`
	ExpectPort uint16 `json:"expect_port,omitempty"`
}

func (*DiscReq) msgTag() {}

type DiscResp struct {
	FlowID     uint32 `json:"flow_id"`
	ObservedIP string `json:"observed_ip"`
	Observed   uint16 `json:"observed_port"`
	FromIP     string `json:"from_ip"`
	FromPort   uint16 `json:"from_port"`
	ChangedIP  string `json:"change_ip"`
	ChangedUDP uint16 `json:"change_port"`
	RTTUs      int64  `json:"rtt_us"`
}

func (*DiscResp) msgTag() {}

// FilterProbe is sent from a *different* server address back to an endpoint:
// reaching the endpoint means its NAT filter let an unsolicited packet through.
type FilterProbe struct {
	FlowID uint32 `json:"flow_id"`
	Token  uint32 `json:"token"`
}

func (*FilterProbe) msgTag() {}

// ---------- signaling (reliable, out-of-band) ----------

type Signal struct {
	What      string `json:"what"` // offer / answer / candidates / restart / restart-ack / relay-select / info
	SessionID string `json:"session_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Cands     []Cand `json:"cands,omitempty"`
	RestartID uint32 `json:"restart_id,omitempty"`
	Note      string `json:"note,omitempty"`
	RelayNode string `json:"relay_node,omitempty"` // negotiated shared relay
	RelayIP   string `json:"relay_ip,omitempty"`
}

func (*Signal) msgTag() {}

// Cand is a transport candidate (mirrors ICE candidates).
type Cand struct {
	Type          string   `json:"type"` // host / srflx / relay / prflx
	IP            string   `json:"ip"`
	Port          uint16   `json:"port"`
	Proto         Protocol `json:"proto"`
	Priority      uint32   `json:"priority"`
	RelayNode     string   `json:"relay_node,omitempty"`
	Predicted     []uint16 `json:"predicted_ports,omitempty"` // srflx port predictions (APDM)
	LocalPort     uint16   `json:"local_port,omitempty"`      // local socket used to obtain this srflx
	Unpredictable bool     `json:"unpredictable,omitempty"`   // APDM with randomized ports: no direct path
	Symmetric     bool     `json:"symmetric,omitempty"`       // outermost mapping is APDM
}

// ---------- relay (TURN-like) ----------

type RelayAlloc struct {
	SessionID string   `json:"session_id"`
	Client    string   `json:"client"`
	Proto     Protocol `json:"proto"`
}

func (*RelayAlloc) msgTag() {}

type RelayAllocAck struct {
	RelayIP   string `json:"relay_ip"`
	RelayPort uint16 `json:"relay_port"`
	Load      int    `json:"load"`
}

func (*RelayAllocAck) msgTag() {}

type RelayBind struct {
	SessionID string `json:"session_id"`
	PeerIP    string `json:"peer_ip"`
	PeerPort  uint16 `json:"peer_port"`
}

func (*RelayBind) msgTag() {}

type RelayData struct {
	SessionID string `json:"session_id"`
	Bytes     int    `json:"bytes"`
}

func (*RelayData) msgTag() {}

// ---------- connectivity checks / data ----------

type ConnCheck struct {
	SessionID string `json:"session_id"`
	RestartID uint32 `json:"restart_id"`
	Use       bool   `json:"use"` // ICE USE-CANDIDATE
}

func (*ConnCheck) msgTag() {}

type ConnCheckAck struct {
	SessionID string `json:"session_id"`
	RestartID uint32 `json:"restart_id"`
}

func (*ConnCheckAck) msgTag() {}

type KeepAlive struct {
	SessionID string `json:"session_id"`
}

func (*KeepAlive) msgTag() {}

type AppData struct {
	SessionID string `json:"session"`
	Bytes     int    `json:"bytes"`
}

func (*AppData) msgTag() {}
