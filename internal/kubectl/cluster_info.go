package kubectl

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterInfo contains detected cluster provider and platform information.
type ClusterInfo struct {
	Provider         string   `json:"provider"`           // eks, aks, gke, openshift, k3s, rke, kubeadm, unknown
	ControlPlaneType string   `json:"control_plane_type"` // managed, self-hosted
	KubeVersion      string   `json:"kube_version"`       // v1.29.1
	Platform         string   `json:"platform"`           // aws, azure, gcp, on-prem, unknown
	DetectedBy       []string `json:"detected_by"`        // which signals were used for detection
}

// DetectClusterInfo detects the cluster provider, platform, and configuration.
func (c *Client) DetectClusterInfo(ctx context.Context) (*ClusterInfo, error) {
	info := &ClusterInfo{
		Provider:         "unknown",
		ControlPlaneType: "unknown",
		Platform:         "unknown",
		DetectedBy:       []string{},
	}

	// Get Kubernetes version from server
	version, err := c.clientset.Discovery().ServerVersion()
	if err == nil {
		info.KubeVersion = version.GitVersion
		info.DetectedBy = append(info.DetectedBy, "server-version")
	}

	// Detect provider from node labels (errors are non-fatal)
	_ = c.detectFromNodeLabels(ctx, info)

	// Detect from kube-system pods if not already detected
	if info.Provider == "unknown" {
		_ = c.detectFromSystemPods(ctx, info)
	}

	// Detect control plane type
	c.detectControlPlaneType(ctx, info)

	return info, nil
}

// detectFromNodeLabels checks node labels for cloud provider signals.
func (c *Client) detectFromNodeLabels(ctx context.Context, info *ClusterInfo) error {
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil
	}

	// Check labels on first node (they're usually consistent)
	for _, node := range nodes.Items {
		labels := node.Labels

		// EKS detection
		if _, ok := labels["eks.amazonaws.com/nodegroup"]; ok {
			info.Provider = "eks"
			info.ControlPlaneType = "managed"
			info.Platform = "aws"
			info.DetectedBy = append(info.DetectedBy, "node-label:eks.amazonaws.com/nodegroup")
			return nil
		}
		if _, ok := labels["alpha.eksctl.io/nodegroup-name"]; ok {
			info.Provider = "eks"
			info.ControlPlaneType = "managed"
			info.Platform = "aws"
			info.DetectedBy = append(info.DetectedBy, "node-label:alpha.eksctl.io/nodegroup-name")
			return nil
		}

		// AKS detection
		if _, ok := labels["kubernetes.azure.com/cluster"]; ok {
			info.Provider = "aks"
			info.ControlPlaneType = "managed"
			info.Platform = "azure"
			info.DetectedBy = append(info.DetectedBy, "node-label:kubernetes.azure.com/cluster")
			return nil
		}
		if _, ok := labels["kubernetes.azure.com/agentpool"]; ok {
			info.Provider = "aks"
			info.ControlPlaneType = "managed"
			info.Platform = "azure"
			info.DetectedBy = append(info.DetectedBy, "node-label:kubernetes.azure.com/agentpool")
			return nil
		}

		// GKE detection
		if _, ok := labels["cloud.google.com/gke-nodepool"]; ok {
			info.Provider = "gke"
			info.ControlPlaneType = "managed"
			info.Platform = "gcp"
			info.DetectedBy = append(info.DetectedBy, "node-label:cloud.google.com/gke-nodepool")
			return nil
		}

		// Scaleway Kapsule detection
		if _, ok := labels["k8s.scaleway.com/managed"]; ok {
			info.Provider = "kapsule"
			info.ControlPlaneType = "managed"
			info.Platform = "scaleway"
			info.DetectedBy = append(info.DetectedBy, "node-label:k8s.scaleway.com/managed")
			return nil
		}

		// OpenShift detection
		if _, ok := labels["node.openshift.io/os_id"]; ok {
			info.Provider = "openshift"
			info.ControlPlaneType = "self-hosted"
			info.Platform = "on-prem" // Could be anywhere
			info.DetectedBy = append(info.DetectedBy, "node-label:node.openshift.io/os_id")
			return nil
		}

		// Rancher RKE detection
		if _, ok := labels["rke.cattle.io/machine"]; ok {
			info.Provider = "rke"
			info.ControlPlaneType = "self-hosted"
			info.DetectedBy = append(info.DetectedBy, "node-label:rke.cattle.io/machine")
			return nil
		}

		// Generic cloud provider labels
		if providerID := node.Spec.ProviderID; providerID != "" {
			if strings.HasPrefix(providerID, "aws://") {
				info.Platform = "aws"
				info.DetectedBy = append(info.DetectedBy, "node-providerid:aws")
			} else if strings.HasPrefix(providerID, "azure://") {
				info.Platform = "azure"
				info.DetectedBy = append(info.DetectedBy, "node-providerid:azure")
			} else if strings.HasPrefix(providerID, "gce://") {
				info.Platform = "gcp"
				info.DetectedBy = append(info.DetectedBy, "node-providerid:gce")
			}
		}
	}

	return nil
}

// detectFromSystemPods checks kube-system pods for provider signals.
func (c *Client) detectFromSystemPods(ctx context.Context, info *ClusterInfo) error {
	pods, err := c.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list kube-system pods: %w", err)
	}

	for _, pod := range pods.Items {
		name := pod.Name

		// K3s detection
		if strings.HasPrefix(name, "k3s-") || strings.Contains(name, "traefik") && strings.Contains(name, "k3s") {
			info.Provider = "k3s"
			info.ControlPlaneType = "self-hosted"
			info.DetectedBy = append(info.DetectedBy, "pod:k3s")
			return nil
		}

		// Kubeadm detection (by component pods)
		if strings.HasPrefix(name, "kube-apiserver-") {
			info.ControlPlaneType = "self-hosted"
			if info.Provider == "unknown" {
				info.Provider = "kubeadm"
			}
			info.DetectedBy = append(info.DetectedBy, "pod:kube-apiserver")
		}

		// MicroK8s detection
		if strings.HasPrefix(name, "microk8s-") || strings.Contains(name, "calico-node") && strings.Contains(pod.Spec.NodeName, "microk8s") {
			info.Provider = "microk8s"
			info.ControlPlaneType = "self-hosted"
			info.DetectedBy = append(info.DetectedBy, "pod:microk8s")
			return nil
		}

		// Kind detection
		if strings.HasPrefix(name, "kindnet-") {
			info.Provider = "kind"
			info.ControlPlaneType = "self-hosted"
			info.Platform = "on-prem"
			info.DetectedBy = append(info.DetectedBy, "pod:kindnet")
			return nil
		}

		// Minikube detection
		if strings.HasPrefix(name, "storage-provisioner") && strings.Contains(pod.Spec.NodeName, "minikube") {
			info.Provider = "minikube"
			info.ControlPlaneType = "self-hosted"
			info.Platform = "on-prem"
			info.DetectedBy = append(info.DetectedBy, "pod:minikube-storage-provisioner")
			return nil
		}
	}

	return nil
}

// detectControlPlaneType determines if the control plane is managed or self-hosted.
func (c *Client) detectControlPlaneType(ctx context.Context, info *ClusterInfo) {
	// If already detected as managed, we're done
	if info.ControlPlaneType == "managed" {
		return
	}

	// Check for control plane components in kube-system
	pods, err := c.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}

	controlPlaneComponents := []string{
		"kube-apiserver",
		"kube-controller-manager",
		"kube-scheduler",
		"etcd",
	}

	foundComponents := 0
	for _, pod := range pods.Items {
		for _, component := range controlPlaneComponents {
			if strings.HasPrefix(pod.Name, component) {
				foundComponents++
				break
			}
		}
	}

	// If we find at least 2 control plane components, it's self-hosted
	if foundComponents >= 2 {
		info.ControlPlaneType = "self-hosted"
		if !slices.Contains(info.DetectedBy, "control-plane-pods") {
			info.DetectedBy = append(info.DetectedBy, "control-plane-pods")
		}
	}
}
