package kubectl

import (
	"testing"
)

func TestClassifyExposure(t *testing.T) {
	tests := []struct {
		name     string
		exposure *WorkloadExposure
		want     string
	}{
		{
			name: "internet-exposed via ingress",
			exposure: &WorkloadExposure{
				Ingresses: []IngressExposure{
					{Name: "test-ingress", Hosts: []string{"app.example.com"}},
				},
				HasNetworkPolicy: false,
			},
			want: "internet",
		},
		{
			name: "internet-exposed via LoadBalancer",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{
					{Name: "test-svc", Type: "LoadBalancer", Ports: []int32{80}},
				},
				HasNetworkPolicy: false,
			},
			want: "internet",
		},
		{
			name: "internet-exposed via NodePort",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{
					{Name: "test-svc", Type: "NodePort", Ports: []int32{30080}},
				},
				HasNetworkPolicy: false,
			},
			want: "internet",
		},
		{
			name: "cluster-wide no network policy",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{
					{Name: "test-svc", Type: "ClusterIP", Ports: []int32{80}},
				},
				HasNetworkPolicy: false,
			},
			want: "cluster",
		},
		{
			name: "cluster-wide allow-all policy",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{
					{Name: "test-svc", Type: "ClusterIP", Ports: []int32{80}},
				},
				HasNetworkPolicy:  true,
				IngressPolicyMode: "allow-all",
			},
			want: "cluster",
		},
		{
			name: "namespace-restricted",
			exposure: &WorkloadExposure{
				Namespace: "default",
				Services: []ServiceExposure{
					{Name: "test-svc", Type: "ClusterIP", Ports: []int32{80}},
				},
				HasNetworkPolicy:  true,
				IngressPolicyMode: "restricted",
				AllowedNamespaces: []string{"default"},
			},
			want: "namespace",
		},
		{
			name: "isolated with default-deny",
			exposure: &WorkloadExposure{
				Services:          []ServiceExposure{},
				HasNetworkPolicy:  true,
				IngressPolicyMode: "default-deny",
			},
			want: "isolated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyExposure(tt.exposure)
			if got != tt.want {
				t.Errorf("classifyExposure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateExposureScore(t *testing.T) {
	// Tests verify CVSS v3.1 Attack Vector alignment
	// Reference: https://www.first.org/cvss/v3.1/specification-document#2-1-1-Attack-Vector-AV
	tests := []struct {
		name     string
		exposure *WorkloadExposure
		want     float64
	}{
		{
			name: "internet maps to CVSS Network (0.85)",
			exposure: &WorkloadExposure{
				ExposureLevel: "internet",
			},
			want: CVSSAttackVectorNetwork, // 0.85
		},
		{
			name: "cluster maps to CVSS Adjacent (0.62)",
			exposure: &WorkloadExposure{
				ExposureLevel: "cluster",
			},
			want: CVSSAttackVectorAdjacent, // 0.62
		},
		{
			name: "namespace maps to CVSS Local (0.55)",
			exposure: &WorkloadExposure{
				ExposureLevel: "namespace",
			},
			want: CVSSAttackVectorLocal, // 0.55
		},
		{
			name: "isolated maps to CVSS Physical (0.20)",
			exposure: &WorkloadExposure{
				ExposureLevel: "isolated",
			},
			want: CVSSAttackVectorPhysical, // 0.20
		},
		{
			name: "unknown defaults to Adjacent (0.62)",
			exposure: &WorkloadExposure{
				ExposureLevel: "",
			},
			want: CVSSAttackVectorAdjacent, // 0.62
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateExposureScore(tt.exposure)
			if got != tt.want {
				t.Errorf("calculateExposureScore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorkloadExposure_GetExposedPorts(t *testing.T) {
	exposure := &WorkloadExposure{
		Services: []ServiceExposure{
			{Name: "svc1", Ports: []int32{80, 443}},
			{Name: "svc2", Ports: []int32{8080, 80}}, // 80 is duplicate
		},
	}

	ports := exposure.GetExposedPorts()

	// Should contain unique ports
	portSet := make(map[int32]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	if len(portSet) != 3 {
		t.Errorf("GetExposedPorts() returned %d unique ports, want 3", len(portSet))
	}

	if !portSet[80] || !portSet[443] || !portSet[8080] {
		t.Errorf("GetExposedPorts() missing expected ports, got %v", ports)
	}
}

func TestWorkloadExposure_GetIngressHosts(t *testing.T) {
	exposure := &WorkloadExposure{
		Ingresses: []IngressExposure{
			{Name: "ing1", Hosts: []string{"app.example.com", "api.example.com"}},
			{Name: "ing2", Hosts: []string{"www.example.com", "app.example.com"}}, // duplicate
		},
	}

	hosts := exposure.GetIngressHosts()

	// Should contain unique hosts
	hostSet := make(map[string]bool)
	for _, h := range hosts {
		hostSet[h] = true
	}

	if len(hostSet) != 3 {
		t.Errorf("GetIngressHosts() returned %d unique hosts, want 3", len(hostSet))
	}
}

func TestWorkloadExposure_HasExternalAccess(t *testing.T) {
	tests := []struct {
		name     string
		exposure *WorkloadExposure
		want     bool
	}{
		{
			name: "has ingress",
			exposure: &WorkloadExposure{
				Ingresses: []IngressExposure{{Name: "test"}},
			},
			want: true,
		},
		{
			name: "has LoadBalancer",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{{Type: "LoadBalancer"}},
			},
			want: true,
		},
		{
			name: "has NodePort",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{{Type: "NodePort"}},
			},
			want: true,
		},
		{
			name: "has ExternalIP",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{{Type: "ClusterIP", ExternalIP: "1.2.3.4"}},
			},
			want: true,
		},
		{
			name: "only ClusterIP",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{{Type: "ClusterIP"}},
			},
			want: false,
		},
		{
			name: "no services",
			exposure: &WorkloadExposure{
				Services: []ServiceExposure{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.exposure.HasExternalAccess(); got != tt.want {
				t.Errorf("HasExternalAccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExposureLevelLabel(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{"internet", "Internet-exposed"},
		{"cluster", "Cluster-accessible"},
		{"namespace", "Namespace-only"},
		{"isolated", "Isolated"},
		{"unknown", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			if got := ExposureLevelLabel(tt.level); got != tt.want {
				t.Errorf("ExposureLevelLabel(%q) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}
