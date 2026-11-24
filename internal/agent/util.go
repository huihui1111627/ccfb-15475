package agent

import (
	"fmt"

	"natlab/internal/sim"
)

func pstr(p uint16) string { return fmt.Sprintf("%d", p) }

func epStr(c sim.Cand) string {
	return fmt.Sprintf("%s:%d/%s(%s)", c.IP, c.Port, c.Proto, c.Type)
}
