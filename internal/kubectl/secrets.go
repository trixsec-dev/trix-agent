package kubectl

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretInfo represents Kubernetes Secret metadata (NOT the actual secret values).
type SecretInfo struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Type      string    `json:"type"` // Opaque, kubernetes.io/tls, etc.
	Keys      []string  `json:"keys"` // Only key names, NOT values
	UsedBy    []string  `json:"used_by"`
	Age       time.Time `json:"age"`
}

// ListSecrets lists all Secrets metadata in a namespace.
// IMPORTANT: This only returns metadata, NOT secret values for security.
// If namespace is empty, lists across all namespaces.
func (c *Client) ListSecrets(ctx context.Context, namespace string) ([]SecretInfo, error) {
	secrets, err := c.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Get workloads to find which secrets are used
	workloads, err := c.ListAllWorkloads(ctx, namespace)
	if err != nil {
		// Don't fail completely, just skip usage tracking
		workloads = nil
	}

	// Build map of secret -> workloads that use it
	secretUsage := c.buildSecretUsageMap(ctx, namespace, workloads)

	var result []SecretInfo
	for _, secret := range secrets.Items {
		// Skip service account tokens (auto-generated)
		if secret.Type == "kubernetes.io/service-account-token" {
			continue
		}

		// Extract only key names from the secret data
		var keys []string
		for key := range secret.Data {
			keys = append(keys, key)
		}

		// Also check stringData (though usually empty at runtime)
		for key := range secret.StringData {
			keys = append(keys, key)
		}

		secretKey := secret.Namespace + "/" + secret.Name
		usedBy := secretUsage[secretKey]

		result = append(result, SecretInfo{
			Name:      secret.Name,
			Namespace: secret.Namespace,
			Type:      string(secret.Type),
			Keys:      keys,
			UsedBy:    usedBy,
			Age:       secret.CreationTimestamp.Time,
		})
	}

	return result, nil
}

// buildSecretUsageMap builds a map of secret key -> workload names that use it.
// This checks both environment variables and volume mounts.
func (c *Client) buildSecretUsageMap(ctx context.Context, _ string, workloads []Workload) map[string][]string {
	usage := make(map[string][]string)

	// If workloads is nil, we need to fetch pod specs directly
	if workloads == nil {
		return usage
	}

	// For each workload, we need to check the underlying pod spec
	// This requires fetching the actual K8s resources again to get full specs
	for _, w := range workloads {
		// Get the pod spec based on workload type
		var secretRefs []string

		switch w.Kind {
		case "Deployment":
			dep, err := c.clientset.AppsV1().Deployments(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			secretRefs = extractSecretRefsFromPodSpec(&dep.Spec.Template.Spec)

		case "DaemonSet":
			ds, err := c.clientset.AppsV1().DaemonSets(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			secretRefs = extractSecretRefsFromPodSpec(&ds.Spec.Template.Spec)

		case "StatefulSet":
			ss, err := c.clientset.AppsV1().StatefulSets(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			secretRefs = extractSecretRefsFromPodSpec(&ss.Spec.Template.Spec)

		case "CronJob":
			cj, err := c.clientset.BatchV1().CronJobs(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			secretRefs = extractSecretRefsFromPodSpec(&cj.Spec.JobTemplate.Spec.Template.Spec)

		case "Job":
			job, err := c.clientset.BatchV1().Jobs(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			secretRefs = extractSecretRefsFromPodSpec(&job.Spec.Template.Spec)
		}

		workloadKey := fmt.Sprintf("%s/%s", w.Kind, w.Name)
		for _, secretName := range secretRefs {
			secretKey := w.Namespace + "/" + secretName
			usage[secretKey] = append(usage[secretKey], workloadKey)
		}
	}

	return usage
}

// extractSecretRefsFromPodSpec extracts all secret names referenced in a pod spec.
func extractSecretRefsFromPodSpec(spec *corev1.PodSpec) []string {
	seen := make(map[string]bool)
	var refs []string

	// Check volumes
	for _, vol := range spec.Volumes {
		if vol.Secret != nil && !seen[vol.Secret.SecretName] {
			refs = append(refs, vol.Secret.SecretName)
			seen[vol.Secret.SecretName] = true
		}
	}

	// Check containers for env and envFrom
	allContainers := append(spec.InitContainers, spec.Containers...)
	for _, container := range allContainers {
		// Check envFrom
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil && !seen[envFrom.SecretRef.Name] {
				refs = append(refs, envFrom.SecretRef.Name)
				seen[envFrom.SecretRef.Name] = true
			}
		}

		// Check individual env vars
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				secretName := env.ValueFrom.SecretKeyRef.Name
				if !seen[secretName] {
					refs = append(refs, secretName)
					seen[secretName] = true
				}
			}
		}
	}

	return refs
}
