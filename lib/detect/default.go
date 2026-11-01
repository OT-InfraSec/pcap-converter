package detect

// Default returns the registry used by the importer.
//
// Protocols without a probe are reported as port-only evidence until their
// content probe exists (DNP3 in plan phase 3, OPC UA when its decoder gains a
// probe). S7 is registered with port 102 as a hint only: the port is shared
// with ISO-TSAP and IEC 61850 MMS, so a connection is S7 when its data TPDUs
// start with the S7 protocol id (ProbeS7); MMS vetoes the hint.
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
		Name:       "S7",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, S7Port}},
		Probe:      ProbeS7,
	})
	r.Register(Protocol{
		Name:       "S7CommPlus",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, S7Port}},
		Probe:      ProbeS7Plus,
	})
	r.Register(Protocol{
		Name:       "DNP3",
		Transports: TCP | UDP,
		HintPorts:  []HintPort{{TCP | UDP, 20000}},
	})
	return r
}
