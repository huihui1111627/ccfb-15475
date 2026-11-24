package server

import (
	"time"

	"natlab/internal/sim"
)

// SignalHandler receives signaling messages delivered to a peer.
type SignalHandler interface {
	OnSignal(e *sim.Engine, s *sim.Signal)
}

// Signaling is a reliable out-of-band rendezvous server (websocket-like).
type Signaling struct {
	id      string
	loc     sim.Location
	clients map[string]SignalHandler
}

func NewSignaling(id string, loc sim.Location, eng *sim.Engine) *Signaling {
	s := &Signaling{id: id, loc: loc, clients: map[string]SignalHandler{}}
	eng.RegisterIP("100.64.0.10", s)
	return s
}

func (s *Signaling) ID() string               { return s.id }
func (s *Signaling) Location() sim.Location   { return s.loc }
func (s *Signaling) AccessRTT() time.Duration { return 0 }
func (s *Signaling) IP() string               { return "100.64.0.10" }

// Register connects a terminal to the signaling service.
func (s *Signaling) Register(clientID string, h SignalHandler) { s.clients[clientID] = h }

func (s *Signaling) OnPacket(e *sim.Engine, p *sim.Packet) {
	sig, ok := p.Msg.(*sim.Signal)
	if !ok {
		return
	}
	e.Log("signal", s.id, "route "+sig.What+" "+sig.From+" -> "+sig.To)
	h, ok := s.clients[sig.To]
	if !ok {
		e.Log("drop", s.id, "unknown signaling peer "+sig.To)
		return
	}
	// reliable delivery: small processing delay, no loss (handled in LinkModel)
	e.Schedule(5*time.Millisecond, func() { h.OnSignal(e, sig) })
}
