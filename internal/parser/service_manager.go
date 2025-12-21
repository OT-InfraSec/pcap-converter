package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// ServiceManager handles service discovery and tracking
type ServiceManager interface {
	// UpdateService updates or creates a service
	UpdateService(ip string, port int, protocol, serviceType string, timestamp time.Time, additionalInfo map[string]interface{}) *model.Service

	// GetService retrieves a service by IP, port, and protocol
	GetService(ip string, port int, protocol string) *model.Service

	// GetAllServices returns all tracked services
	GetAllServices() []*model.Service

	// Clear removes all services from tracking
	Clear()
}

// DefaultServiceManager implements ServiceManager
type DefaultServiceManager struct {
	services map[string]*model.Service
	tenantID string
}

// NewDefaultServiceManager creates a new service manager
func NewDefaultServiceManager(tenantID string) *DefaultServiceManager {
	return &DefaultServiceManager{
		services: make(map[string]*model.Service),
		tenantID: tenantID,
	}
}

// UpdateService updates or creates a service
func (sm *DefaultServiceManager) UpdateService(ip string, port int, protocol, serviceType string,
	timestamp time.Time, additionalInfo map[string]interface{}) *model.Service {

	serviceKey := fmt.Sprintf("%s:%d:%s", ip, port, protocol)
	service, exists := sm.services[serviceKey]

	if !exists {
		// Create new service
		additionalData := ""
		if additionalInfo != nil {
			if jsonData, err := json.Marshal(additionalInfo); err == nil {
				additionalData = string(jsonData)
			}
		}

		service = &model.Service{
			TenantID:       sm.tenantID,
			IP:             net.ParseIP(ip),
			Port:           port,
			Protocol:       protocol,
			ServiceType:    serviceType,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			AdditionalData: additionalData,
		}
		sm.services[serviceKey] = service
	} else {
		// Update existing service
		if timestamp.Before(service.FirstSeen) {
			service.FirstSeen = timestamp
		}
		if timestamp.After(service.LastSeen) {
			service.LastSeen = timestamp
		}

		// Merge additional info if provided
		if additionalInfo != nil {
			if service.AdditionalData != "" {
				// Parse existing data
				var existingData map[string]interface{}
				if err := json.Unmarshal([]byte(service.AdditionalData), &existingData); err == nil {
					// Merge new data
					for k, v := range additionalInfo {
						existingData[k] = v
					}
					// Convert back to JSON
					if merged, err := json.Marshal(existingData); err == nil {
						service.AdditionalData = string(merged)
					}
				}
			} else {
				// No existing data, just set new data
				if jsonData, err := json.Marshal(additionalInfo); err == nil {
					service.AdditionalData = string(jsonData)
				}
			}
		}

		// Update service type if different and not empty
		if serviceType != "" && service.ServiceType != serviceType {
			// Keep the more specific service type
			if service.ServiceType == "" || len(serviceType) > len(service.ServiceType) {
				service.ServiceType = serviceType
			}
		}

		sm.services[serviceKey] = service
	}

	return service
}

// GetService retrieves a service by IP, port, and protocol
func (sm *DefaultServiceManager) GetService(ip string, port int, protocol string) *model.Service {
	serviceKey := fmt.Sprintf("%s:%d:%s", ip, port, protocol)
	return sm.services[serviceKey]
}

// GetAllServices returns all tracked services
func (sm *DefaultServiceManager) GetAllServices() []*model.Service {
	services := make([]*model.Service, 0, len(sm.services))
	for _, service := range sm.services {
		services = append(services, service)
	}
	return services
}

// Clear removes all services from tracking
func (sm *DefaultServiceManager) Clear() {
	sm.services = make(map[string]*model.Service)
}
