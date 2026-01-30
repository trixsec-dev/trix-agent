package kubectl

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NamespaceInfo represents a Kubernetes Namespace with PSS labels.
type NamespaceInfo struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Status      string            `json:"status"`
	Age         time.Time         `json:"age"`
	// PodSecurityStandard labels extracted for convenience
	PSSEnforce string `json:"pss_enforce,omitempty"` // pod-security.kubernetes.io/enforce
	PSSAudit   string `json:"pss_audit,omitempty"`   // pod-security.kubernetes.io/audit
	PSSWarn    string `json:"pss_warn,omitempty"`    // pod-security.kubernetes.io/warn
}

// ListNamespaces lists all Namespaces with their labels and PSS configuration.
func (c *Client) ListNamespaces(ctx context.Context) ([]NamespaceInfo, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	var result []NamespaceInfo
	for _, ns := range namespaces.Items {
		info := NamespaceInfo{
			Name:        ns.Name,
			Labels:      ns.Labels,
			Annotations: ns.Annotations,
			Status:      string(ns.Status.Phase),
			Age:         ns.CreationTimestamp.Time,
		}

		// Extract PSS labels if present
		if ns.Labels != nil {
			info.PSSEnforce = ns.Labels["pod-security.kubernetes.io/enforce"]
			info.PSSAudit = ns.Labels["pod-security.kubernetes.io/audit"]
			info.PSSWarn = ns.Labels["pod-security.kubernetes.io/warn"]
		}

		result = append(result, info)
	}

	return result, nil
}
