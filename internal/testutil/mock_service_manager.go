package testutil

import (
	"net"
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// MockServiceManager is a mock implementation of ServiceManager for testing
type MockServiceManager struct {
	UpdateServiceFunc  func(ip string, port int, protocol, serviceType string, timestamp time.Time, additionalInfo map[string]interface{}) *model.Service
	GetServiceFunc     func(ip string, port int, protocol string) *model.Service
	GetAllServicesFunc func() []*model.Service
	ClearFunc          func()

	UpdateServiceCalls  []MockServiceManagerUpdateServiceCall
	GetServiceCalls     []MockServiceManagerGetServiceCall
	GetAllServicesCalls int
	ClearCalls          int
}

type MockServiceManagerUpdateServiceCall struct {
	IP, Protocol, ServiceType string
	Port                      int
	Timestamp                 time.Time
	AdditionalInfo            map[string]interface{}
}

type MockServiceManagerGetServiceCall struct {
	IP, Protocol string
	Port         int
}

func (m *MockServiceManager) UpdateService(ip string, port int, protocol, serviceType string, timestamp time.Time, additionalInfo map[string]interface{}) *model.Service {
	m.UpdateServiceCalls = append(m.UpdateServiceCalls, MockServiceManagerUpdateServiceCall{
		IP: ip, Port: port, Protocol: protocol, ServiceType: serviceType,
		Timestamp: timestamp, AdditionalInfo: additionalInfo,
	})

	if m.UpdateServiceFunc != nil {
		return m.UpdateServiceFunc(ip, port, protocol, serviceType, timestamp, additionalInfo)
	}
	
	// Default implementation
	return &model.Service{
		IP:       net.ParseIP(ip),
		Port:     port,
		Protocol: protocol,
	}
}

func (m *MockServiceManager) GetService(ip string, port int, protocol string) *model.Service {
	m.GetServiceCalls = append(m.GetServiceCalls, MockServiceManagerGetServiceCall{
		IP: ip, Port: port, Protocol: protocol,
	})

	if m.GetServiceFunc != nil {
		return m.GetServiceFunc(ip, port, protocol)
	}

	return nil
}

func (m *MockServiceManager) GetAllServices() []*model.Service {
	m.GetAllServicesCalls++

	if m.GetAllServicesFunc != nil {
		return m.GetAllServicesFunc()
	}

	return []*model.Service{}
}

func (m *MockServiceManager) Clear() {
	m.ClearCalls++

	if m.ClearFunc != nil {
		m.ClearFunc()
	}
}
