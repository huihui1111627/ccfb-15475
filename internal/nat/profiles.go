package nat

import "time"

// Archetype is a reusable, named NAT configuration used to build the matrix.
type Archetype struct {
	ID    string
	Label string
	Chain []Profile // 1 = single NAT, 2 = nested (inner first)
}

// Archetypes returns the full site catalog. The last two archetypes emulate
// protocol-blocking networks (UDP or TCP firewalled at the outer device).
func Archetypes() []Archetype {
	to := 30 * time.Second
	long := 3 * time.Minute
	return []Archetype{
		{"fullcone", "Full cone (EIM+EIF, preserve)", []Profile{{
			Name: "nat-fullcone", Mapping: EIM, Filter: EIF, Port: PortPreserve, MappingTimeout: long,
		}}},
		{"restricted", "Restricted cone (EIM+ADF, preserve)", []Profile{{
			Name: "nat-restricted", Mapping: EIM, Filter: ADF, Port: PortPreserve, MappingTimeout: long,
		}}},
		{"portrestricted", "Port-restricted cone (EIM+APDF, preserve)", []Profile{{
			Name: "nat-portrestricted", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: to,
		}}},
		{"symmetric", "Symmetric (APDM+APDF, preserve)", []Profile{{
			Name: "nat-symmetric", Mapping: APDM, Filter: APDF, Port: PortPreserve, MappingTimeout: to,
		}}},
		{"symmetric-inc", "Symmetric, incrementing ports", []Profile{{
			Name: "nat-sym-inc", Mapping: APDM, Filter: APDF, Port: PortIncrement, MappingTimeout: to, TimeoutJitter: 4 * time.Second,
		}}},
		{"symmetric-rand", "Symmetric, random ports", []Profile{{
			Name: "nat-sym-rand", Mapping: APDM, Filter: APDF, Port: PortRandom, MappingTimeout: to,
		}}},
		{"addr-dependent", "Address-dependent mapping (ADM+ADF)", []Profile{{
			Name: "nat-adm", Mapping: ADM, Filter: ADF, Port: PortIncrement, MappingTimeout: to,
		}}},
		{"short-timeout", "Cone with 12s mapping timeout", []Profile{{
			Name: "nat-short", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: 12 * time.Second,
		}}},
		{"nested-cone-sym", "Double NAT: cone behind symmetric", []Profile{
			{Name: "nat-inner", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: long, Hairpin: true},
			{Name: "nat-outer", Mapping: APDM, Filter: APDF, Port: PortIncrement, MappingTimeout: to, Hairpin: true},
		}},
		{"nested-two-cone", "Double NAT: cone behind cone", []Profile{
			{Name: "nat-inner", Mapping: EIM, Filter: ADF, Port: PortPreserve, MappingTimeout: long, Hairpin: true},
			{Name: "nat-outer", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: long, Hairpin: true},
		}},
		{"udp-blocked", "Firewall: UDP blocked (TCP reachable)", []Profile{{
			Name: "nat-noudp", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: to, BlockUDP: true,
		}}},
		{"tcp-blocked", "Firewall: TCP blocked (UDP reachable)", []Profile{{
			Name: "nat-notcp", Mapping: EIM, Filter: APDF, Port: PortPreserve, MappingTimeout: to, BlockTCP: true,
		}}},
	}
}

// ArchetypeByID looks one up.
func ArchetypeByID(id string) Archetype {
	for _, a := range Archetypes() {
		if a.ID == id {
			return a
		}
	}
	panic("unknown archetype " + id)
}
