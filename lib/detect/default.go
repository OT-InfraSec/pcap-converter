package detect

// Default returns the registry used by the importer.
//
// Protocols without a probe are reported as port-only evidence until their
// content probe exists (OPC UA, when its decoder gains a probe). S7 is registered with port 102 as a hint only: the port is shared
// with ISO-TSAP and IEC 61850 MMS, so a connection is S7 when its data TPDUs
// start with the S7 protocol id (ProbeS7); MMS vetoes the hint.
func Default() *Registry {
	r := &Registry{}
	r.Register(Protocol{
		Name:       "EtherNet/IP",
		Key:        "ethernetip",
		Industrial: true,
		Label:      "EtherNet/IP(TCP)",
		UDPLabel:   "EtherNet/IP(UDP)",
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
		Key:        "opcua",
		Industrial: true,
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, 4840}},
	})
	r.Register(Protocol{
		Name:       "Modbus",
		Key:        "modbus",
		Industrial: true,
		Label:      "modbus",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, ModbusPort}},
		Probe:      ProbeModbusTCP,
	})
	r.Register(Protocol{
		Name:       "S7",
		Key:        "s7",
		Industrial: true,
		Label:      "s7",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, S7Port}},
		Probe:      ProbeS7,
	})
	r.Register(Protocol{
		Name:       "S7CommPlus",
		Key:        "s7commplus",
		Industrial: true,
		Label:      "s7commplus",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, S7Port}},
		Probe:      ProbeS7Plus,
	})
	r.Register(Protocol{
		Name:       "SMB",
		Key:        "smb",
		Label:      "smb",
		Transports: TCP,
		HintPorts:  []HintPort{{TCP, SMBPort}, {TCP, SMBNetBIOSPort}},
		Probe:      ProbeSMB,
	})
	r.Register(Protocol{
		Name:       "NetBIOS NS",
		Key:        "nbns",
		Label:      "nbns",
		Transports: UDP,
		HintPorts:  []HintPort{{UDP, NBNSPort}},
		Probe:      ProbeNBNS,
	})
	r.Register(Protocol{
		Name:       "DNP3",
		Key:        "dnp3",
		Industrial: true,
		Label:      "dnp3",
		Transports: TCP | UDP,
		HintPorts:  []HintPort{{TCP | UDP, DNP3Port}},
		Probe:      ProbeDNP3,
	})
	return r
}
