package types

type ResourceType string

const (
	ResourceTypePeer             ResourceType = "peer"
	ResourceTypeDomain           ResourceType = "domain"
	ResourceTypeHost             ResourceType = "host"
	ResourceTypeSubnet           ResourceType = "subnet"
	ResourceTypeCloudIntegration ResourceType = "cloud_integration"
)

func (t ResourceType) Valid() bool {
	switch t {
	case ResourceTypePeer, ResourceTypeDomain, ResourceTypeHost, ResourceTypeSubnet, ResourceTypeCloudIntegration:
		return true
	default:
		return false
	}
}
