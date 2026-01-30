package kubectl

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceAccountInfo represents a Kubernetes ServiceAccount with RBAC bindings.
type ServiceAccountInfo struct {
	Name                  string                   `json:"name"`
	Namespace             string                   `json:"namespace"`
	Secrets               []string                 `json:"secrets"`
	ImagePullSecrets      []string                 `json:"image_pull_secrets"`
	AutomountServiceToken bool                     `json:"automount_service_token"`
	RoleBindings          []RoleBindingInfo        `json:"role_bindings"`
	ClusterRoleBindings   []ClusterRoleBindingInfo `json:"cluster_role_bindings"`
}

// RoleBindingInfo represents a RoleBinding or ClusterRoleBinding reference.
type RoleBindingInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	RoleName  string `json:"role_name"`
	RoleKind  string `json:"role_kind"` // Role or ClusterRole
}

// ClusterRoleBindingInfo represents a ClusterRoleBinding.
type ClusterRoleBindingInfo struct {
	Name     string `json:"name"`
	RoleName string `json:"role_name"`
}

// ListServiceAccounts lists all ServiceAccounts in a namespace with their RBAC bindings.
// If namespace is empty, lists across all namespaces.
func (c *Client) ListServiceAccounts(ctx context.Context, namespace string) ([]ServiceAccountInfo, error) {
	// Get all ServiceAccounts
	sas, err := c.clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	// Get all RoleBindings for lookup
	roleBindings, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list role bindings: %w", err)
	}

	// Get all ClusterRoleBindings for lookup
	clusterRoleBindings, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	// Build lookup maps: sa key -> bindings
	// Key format: namespace/name
	saRoleBindings := make(map[string][]RoleBindingInfo)
	saClusterRoleBindings := make(map[string][]ClusterRoleBindingInfo)

	for _, rb := range roleBindings.Items {
		for _, subject := range rb.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			// Handle cross-namespace bindings
			saNamespace := subject.Namespace
			if saNamespace == "" {
				saNamespace = rb.Namespace
			}
			key := saNamespace + "/" + subject.Name
			saRoleBindings[key] = append(saRoleBindings[key], RoleBindingInfo{
				Name:      rb.Name,
				Namespace: rb.Namespace,
				RoleName:  rb.RoleRef.Name,
				RoleKind:  rb.RoleRef.Kind,
			})
		}
	}

	for _, crb := range clusterRoleBindings.Items {
		for _, subject := range crb.Subjects {
			if subject.Kind != "ServiceAccount" {
				continue
			}
			key := subject.Namespace + "/" + subject.Name
			saClusterRoleBindings[key] = append(saClusterRoleBindings[key], ClusterRoleBindingInfo{
				Name:     crb.Name,
				RoleName: crb.RoleRef.Name,
			})
		}
	}

	var result []ServiceAccountInfo
	for _, sa := range sas.Items {
		key := sa.Namespace + "/" + sa.Name

		// Extract secret names
		var secrets []string
		for _, s := range sa.Secrets {
			secrets = append(secrets, s.Name)
		}

		// Extract image pull secret names
		var imagePullSecrets []string
		for _, s := range sa.ImagePullSecrets {
			imagePullSecrets = append(imagePullSecrets, s.Name)
		}

		// Determine automount setting (default is true)
		automount := true
		if sa.AutomountServiceAccountToken != nil {
			automount = *sa.AutomountServiceAccountToken
		}

		result = append(result, ServiceAccountInfo{
			Name:                  sa.Name,
			Namespace:             sa.Namespace,
			Secrets:               secrets,
			ImagePullSecrets:      imagePullSecrets,
			AutomountServiceToken: automount,
			RoleBindings:          saRoleBindings[key],
			ClusterRoleBindings:   saClusterRoleBindings[key],
		})
	}

	return result, nil
}

// ListRoleBindings lists all RoleBindings in a namespace.
// If namespace is empty, lists across all namespaces.
func (c *Client) ListRoleBindings(ctx context.Context, namespace string) ([]RoleBindingInfo, error) {
	rbs, err := c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list role bindings: %w", err)
	}

	var result []RoleBindingInfo
	for _, rb := range rbs.Items {
		result = append(result, RoleBindingInfo{
			Name:      rb.Name,
			Namespace: rb.Namespace,
			RoleName:  rb.RoleRef.Name,
			RoleKind:  rb.RoleRef.Kind,
		})
	}

	return result, nil
}

// ListClusterRoleBindings lists all ClusterRoleBindings.
func (c *Client) ListClusterRoleBindings(ctx context.Context) ([]ClusterRoleBindingInfo, error) {
	crbs, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	var result []ClusterRoleBindingInfo
	for _, crb := range crbs.Items {
		result = append(result, ClusterRoleBindingInfo{
			Name:     crb.Name,
			RoleName: crb.RoleRef.Name,
		})
	}

	return result, nil
}
