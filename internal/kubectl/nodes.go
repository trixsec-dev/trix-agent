package kubectl

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeInfo represents a Kubernetes Node.
type NodeInfo struct {
	Name             string            `json:"name"`
	OS               string            `json:"os"`
	Architecture     string            `json:"architecture"`
	KernelVersion    string            `json:"kernel_version"`
	KubeletVersion   string            `json:"kubelet_version"`
	ContainerRuntime string            `json:"container_runtime"`
	Capacity         ResourceInfo      `json:"capacity"`
	Allocatable      ResourceInfo      `json:"allocatable"`
	Conditions       []NodeCondition   `json:"conditions"`
	Taints           []Taint           `json:"taints"`
	Labels           map[string]string `json:"labels"`
}

// ResourceInfo represents resource capacity/allocatable values.
type ResourceInfo struct {
	CPU              string `json:"cpu"`
	Memory           string `json:"memory"`
	Pods             string `json:"pods"`
	EphemeralStorage string `json:"ephemeral_storage,omitempty"`
}

// NodeCondition represents a node condition.
type NodeCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Taint represents a node taint.
type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

// ListNodes lists all Nodes in the cluster with their status and configuration.
func (c *Client) ListNodes(ctx context.Context) ([]NodeInfo, error) {
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	var result []NodeInfo
	for _, node := range nodes.Items {
		// Extract node info from status
		nodeInfo := node.Status.NodeInfo

		// Parse container runtime (format: "containerd://1.6.12")
		containerRuntime := nodeInfo.ContainerRuntimeVersion
		if parts := strings.SplitN(containerRuntime, "://", 2); len(parts) == 2 {
			containerRuntime = parts[0] + " " + parts[1]
		}

		// Build conditions list
		var conditions []NodeCondition
		for _, c := range node.Status.Conditions {
			conditions = append(conditions, NodeCondition{
				Type:    string(c.Type),
				Status:  string(c.Status),
				Reason:  c.Reason,
				Message: c.Message,
			})
		}

		// Build taints list
		var taints []Taint
		for _, t := range node.Spec.Taints {
			taints = append(taints, Taint{
				Key:    t.Key,
				Value:  t.Value,
				Effect: string(t.Effect),
			})
		}

		// Extract capacity and allocatable
		capacity := node.Status.Capacity
		allocatable := node.Status.Allocatable

		result = append(result, NodeInfo{
			Name:             node.Name,
			OS:               nodeInfo.OperatingSystem,
			Architecture:     nodeInfo.Architecture,
			KernelVersion:    nodeInfo.KernelVersion,
			KubeletVersion:   nodeInfo.KubeletVersion,
			ContainerRuntime: containerRuntime,
			Labels:           node.Labels,
			Capacity: ResourceInfo{
				CPU:              capacity.Cpu().String(),
				Memory:           capacity.Memory().String(),
				Pods:             capacity.Pods().String(),
				EphemeralStorage: capacity.StorageEphemeral().String(),
			},
			Allocatable: ResourceInfo{
				CPU:              allocatable.Cpu().String(),
				Memory:           allocatable.Memory().String(),
				Pods:             allocatable.Pods().String(),
				EphemeralStorage: allocatable.StorageEphemeral().String(),
			},
			Conditions: conditions,
			Taints:     taints,
		})
	}

	return result, nil
}
