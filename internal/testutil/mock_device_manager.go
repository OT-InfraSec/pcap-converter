package testutil

import (
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// MockDeviceManager is a mock implementation of DeviceManager for testing
type MockDeviceManager struct {
	UpsertDeviceFunc                   func(address, addressType string, timestamp time.Time, addressSubType, macAddress, additionalData string, isDestination bool) *model.Device
	GetDeviceFunc                      func(address, addressType string) *model.Device
	GetAllDevicesFunc                  func() []*model.Device
	UpdateDeviceWithIndustrialInfoFunc func(deviceIP string, protocolInfo model.IndustrialProtocolInfo, isDestination bool)
	GetDeviceCounterFunc               func() int64
	ClearFunc                          func()

	UpsertDeviceCalls                   []MockDeviceManagerUpsertDeviceCall
	GetDeviceCalls                      []MockDeviceManagerGetDeviceCall
	GetAllDevicesCalls                  int
	UpdateDeviceWithIndustrialInfoCalls []MockDeviceManagerUpdateIndustrialInfoCall
	GetDeviceCounterCalls               int
	ClearCalls                          int
}

type MockDeviceManagerUpsertDeviceCall struct {
	Address, AddressType, AddressSubType, MACAddress, AdditionalData string
	Timestamp                                                        time.Time
	IsDestination                                                    bool
}

type MockDeviceManagerGetDeviceCall struct {
	Address, AddressType string
}

type MockDeviceManagerUpdateIndustrialInfoCall struct {
	DeviceIP      string
	ProtocolInfo  model.IndustrialProtocolInfo
	IsDestination bool
}

func (m *MockDeviceManager) UpsertDevice(address, addressType string, timestamp time.Time, addressSubType, macAddress, additionalData string, isDestination bool) *model.Device {
	m.UpsertDeviceCalls = append(m.UpsertDeviceCalls, MockDeviceManagerUpsertDeviceCall{
		Address: address, AddressType: addressType, AddressSubType: addressSubType,
		MACAddress: macAddress, AdditionalData: additionalData,
		Timestamp: timestamp, IsDestination: isDestination,
	})

	if m.UpsertDeviceFunc != nil {
		return m.UpsertDeviceFunc(address, addressType, timestamp, addressSubType, macAddress, additionalData, isDestination)
	}

	// Default implementation
	return &model.Device{
		Address:     address,
		AddressType: addressType,
	}
}

func (m *MockDeviceManager) GetDevice(address, addressType string) *model.Device {
	m.GetDeviceCalls = append(m.GetDeviceCalls, MockDeviceManagerGetDeviceCall{
		Address: address, AddressType: addressType,
	})

	if m.GetDeviceFunc != nil {
		return m.GetDeviceFunc(address, addressType)
	}

	return nil
}

func (m *MockDeviceManager) GetAllDevices() []*model.Device {
	m.GetAllDevicesCalls++

	if m.GetAllDevicesFunc != nil {
		return m.GetAllDevicesFunc()
	}

	return []*model.Device{}
}

func (m *MockDeviceManager) UpdateDeviceWithIndustrialInfo(deviceIP string, protocolInfo model.IndustrialProtocolInfo, isDestination bool) {
	m.UpdateDeviceWithIndustrialInfoCalls = append(m.UpdateDeviceWithIndustrialInfoCalls, MockDeviceManagerUpdateIndustrialInfoCall{
		DeviceIP: deviceIP, ProtocolInfo: protocolInfo, IsDestination: isDestination,
	})

	if m.UpdateDeviceWithIndustrialInfoFunc != nil {
		m.UpdateDeviceWithIndustrialInfoFunc(deviceIP, protocolInfo, isDestination)
	}
}

func (m *MockDeviceManager) GetDeviceCounter() int64 {
	m.GetDeviceCounterCalls++

	if m.GetDeviceCounterFunc != nil {
		return m.GetDeviceCounterFunc()
	}

	return 0
}

func (m *MockDeviceManager) Clear() {
	m.ClearCalls++

	if m.ClearFunc != nil {
		m.ClearFunc()
	}
}
