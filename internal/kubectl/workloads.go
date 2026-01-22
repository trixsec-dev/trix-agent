package kubectl

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Workload represents a Kubernetes workload resource
type Workload struct {
	Kind       string      `json:"kind"`
	Namespace  string      `json:"namespace"`
	Name       string      `json:"name"`
	Containers []Container `json:"containers"`
	ScanStatus string      `json:"scan_status"` // scanned, pending, failed, unknown
}

// Container represents a container within a workload
type Container struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ListDeployments lists all Deployments in a namespace
// If namespace is empty, lists across all namespaces
func (c *Client) ListDeployments(ctx context.Context, namespace string) ([]Workload, error) {
	deployments, err := c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	var workloads []Workload
	for _, dep := range deployments.Items {
		var containers []Container
		for _, c := range dep.Spec.Template.Spec.Containers {
			containers = append(containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		workloads = append(workloads, Workload{
			Kind:       "Deployment",
			Namespace:  dep.Namespace,
			Name:       dep.Name,
			Containers: containers,
		})
	}
	return workloads, nil
}

// ListDaemonSets lists all DaemonSets in a namespace
func (c *Client) ListDaemonSets(ctx context.Context, namespace string) ([]Workload, error) {
	daemonsets, err := c.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}

	var workloads []Workload
	for _, ds := range daemonsets.Items {
		var containers []Container
		for _, c := range ds.Spec.Template.Spec.Containers {
			containers = append(containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		workloads = append(workloads, Workload{
			Kind:       "DaemonSet",
			Namespace:  ds.Namespace,
			Name:       ds.Name,
			Containers: containers,
		})
	}
	return workloads, nil
}

// ListStatefulSets lists all StatefulSets in a namespace
func (c *Client) ListStatefulSets(ctx context.Context, namespace string) ([]Workload, error) {
	statefulsets, err := c.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}

	var workloads []Workload
	for _, ss := range statefulsets.Items {
		var containers []Container
		for _, c := range ss.Spec.Template.Spec.Containers {
			containers = append(containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		workloads = append(workloads, Workload{
			Kind:       "StatefulSet",
			Namespace:  ss.Namespace,
			Name:       ss.Name,
			Containers: containers,
		})
	}
	return workloads, nil
}

// ListCronJobs lists all CronJobs in a namespace
func (c *Client) ListCronJobs(ctx context.Context, namespace string) ([]Workload, error) {
	cronjobs, err := c.clientset.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cronjobs: %w", err)
	}

	var workloads []Workload
	for _, cj := range cronjobs.Items {
		var containers []Container
		for _, c := range cj.Spec.JobTemplate.Spec.Template.Spec.Containers {
			containers = append(containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		workloads = append(workloads, Workload{
			Kind:       "CronJob",
			Namespace:  cj.Namespace,
			Name:       cj.Name,
			Containers: containers,
		})
	}
	return workloads, nil
}

// ListJobs lists all Jobs in a namespace (excluding those owned by CronJobs or managed by Trivy)
func (c *Client) ListJobs(ctx context.Context, namespace string) ([]Workload, error) {
	jobs, err := c.clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	var workloads []Workload
	for _, job := range jobs.Items {
		// Skip Jobs owned by CronJobs (they're tracked via CronJob)
		isOwnedByCronJob := false
		for _, ref := range job.OwnerReferences {
			if ref.Kind == "CronJob" {
				isOwnedByCronJob = true
				break
			}
		}
		if isOwnedByCronJob {
			continue
		}

		// Skip Trivy scan jobs (ephemeral jobs created by trivy-operator)
		if job.Labels["app.kubernetes.io/managed-by"] == "trivy-operator" {
			continue
		}

		var containers []Container
		for _, c := range job.Spec.Template.Spec.Containers {
			containers = append(containers, Container{
				Name:  c.Name,
				Image: c.Image,
			})
		}

		workloads = append(workloads, Workload{
			Kind:       "Job",
			Namespace:  job.Namespace,
			Name:       job.Name,
			Containers: containers,
		})
	}
	return workloads, nil
}

// ListAllWorkloads lists all Deployments, DaemonSets, StatefulSets, CronJobs, and Jobs in a namespace
func (c *Client) ListAllWorkloads(ctx context.Context, namespace string) ([]Workload, error) {
	var allWorkloads []Workload

	deployments, err := c.ListDeployments(ctx, namespace)
	if err != nil {
		return nil, err
	}
	allWorkloads = append(allWorkloads, deployments...)

	daemonsets, err := c.ListDaemonSets(ctx, namespace)
	if err != nil {
		return nil, err
	}
	allWorkloads = append(allWorkloads, daemonsets...)

	statefulsets, err := c.ListStatefulSets(ctx, namespace)
	if err != nil {
		return nil, err
	}
	allWorkloads = append(allWorkloads, statefulsets...)

	cronjobs, err := c.ListCronJobs(ctx, namespace)
	if err != nil {
		return nil, err
	}
	allWorkloads = append(allWorkloads, cronjobs...)

	jobs, err := c.ListJobs(ctx, namespace)
	if err != nil {
		return nil, err
	}
	allWorkloads = append(allWorkloads, jobs...)

	return allWorkloads, nil
}
