package detect

// Default returns the registry used by the importer.
//
// Protocols without a probe are reported as port-only evidence until their
// content probe exists (DNP3 in plan phase 3, OPC UA when its decoder gains a
// probe). S7 is deliberately absent: port
// 102 is shared with ISO-TSAP and IEC 61850 MMS, and no S7 decoder exists.
func Default() *Registry {
	r := &Registry{}
	r.Register(Protocol{
		Name:       "EtherNet/IP",
		Transports: TCP | UDP,
		HintPorts: []HintPort{
			{TCP | UDP, ENIPPortExplicit},
			{UDP, ENIPPortImplicit},
		},
		Probe:    ProbeENIPEncapsulation,
		ProbeUDP: ProbeENIPUDP,
	})
	r.Register(Protocol{
		Name:       "OPC UA",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, 4840}},
	})
	r.Register(Protocol{
		Name:       "Modbus",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, ModbusPort}},
		Probe:      ProbeModbusTCP,
	})
	r.Register(Protocol{
		Name:       "DNP3",
		Transports: TCP | UDP,
		HintPorts:  []HintPort{{TCP | UDP, 20000}},
	})
	return r
}
