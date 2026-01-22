package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/trixsec-dev/trix-agent/internal/kubectl"
	"github.com/trixsec-dev/trix-agent/internal/trivy"
)

const (
	saasBatchSize  = 50 // Send events in batches to avoid timeouts
	saasMaxRetries = 3  // Number of retries per batch
)

// SaasResult contains the result of a SaaS sync operation.
type SaasResult struct {
	SyncedIDs []string // IDs that were successfully synced
	FailedIDs []string // IDs that failed to sync
	Err       error    // First error encountered (if any)
}

type Notifier struct {
	config     *Config
	httpClient *http.Client
	logger     *slog.Logger
}

func NewNotifier(config *Config, logger *slog.Logger) *Notifier {
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// SendSaas sends events to the SaaS backend with retry logic.
// Returns a SaasResult indicating which events succeeded/failed.
func (n *Notifier) SendSaas(ctx context.Context, events []VulnerabilityEvent) *SaasResult {
	if n.config.SaasEndpoint == "" {
		return &SaasResult{}
	}

	result := &SaasResult{}
	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/events"

	// Send events in batches
	for i := 0; i < len(events); i += saasBatchSize {
		end := i + saasBatchSize
		if end > len(events) {
			end = len(events)
		}
		batch := events[i:end]

		// Collect IDs from this batch
		batchIDs := make([]string, 0, len(batch))
		for _, e := range batch {
			if e.ID != "" {
				batchIDs = append(batchIDs, e.ID)
			}
		}

		payload := map[string]interface{}{
			"cluster_name": n.config.ClusterName,
			"trix_version": n.config.Version,
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"events":       batch,
		}

		// Retry with exponential backoff
		var lastErr error
		for attempt := 0; attempt < saasMaxRetries; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, 4s
				n.logger.Debug("retrying saas batch", "attempt", attempt+1, "backoff", backoff)
				select {
				case <-ctx.Done():
					result.FailedIDs = append(result.FailedIDs, batchIDs...)
					result.Err = ctx.Err()
					return result
				case <-time.After(backoff):
				}
			}

			if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
				lastErr = err
				n.logger.Warn("saas batch failed", "batch", i/saasBatchSize+1, "attempt", attempt+1, "error", err)
				continue
			}

			// Success
			result.SyncedIDs = append(result.SyncedIDs, batchIDs...)
			n.logger.Info("saas batch sent", "batch", i/saasBatchSize+1, "events", len(batch), "total", len(events))
			lastErr = nil
			break
		}

		if lastErr != nil {
			// All retries failed for this batch
			result.FailedIDs = append(result.FailedIDs, batchIDs...)
			if result.Err == nil {
				result.Err = fmt.Errorf("batch %d-%d failed after %d retries: %w", i, end, saasMaxRetries, lastErr)
			}
			n.logger.Error("saas batch failed permanently",
				"batch", i/saasBatchSize+1,
				"events", len(batch),
				"failed_ids", len(batchIDs),
				"error", lastErr,
			)
		}
	}

	return result
}

// SendSaasCompliance sends compliance events to the SaaS backend.
func (n *Notifier) SendSaasCompliance(ctx context.Context, events []ComplianceEvent) error {
	if n.config.SaasEndpoint == "" {
		return nil
	}

	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/compliance"

	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"trix_version": n.config.Version,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"compliance":   events,
	}

	if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
		return fmt.Errorf("saas compliance sync failed: %w", err)
	}

	n.logger.Info("saas compliance sent", "controls", len(events))
	return nil
}

// SendSaasDetailedCompliance sends detailed compliance checks to the SaaS backend.
// This is the new stateless sync - SAAS determines new/fixed based on last_seen.
func (n *Notifier) SendSaasDetailedCompliance(ctx context.Context, checks []DetailedComplianceCheck) error {
	if n.config.SaasEndpoint == "" {
		return nil
	}

	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/compliance/checks"

	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"trix_version": n.config.Version,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"checks":       checks,
	}

	if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
		return fmt.Errorf("saas detailed compliance sync failed: %w", err)
	}

	n.logger.Info("saas detailed compliance sent", "checks", len(checks))
	return nil
}

// SendSaasWorkloads sends workload inventory to the SaaS backend.
// This enables the platform to show all workloads, including those without vulnerabilities.
func (n *Notifier) SendSaasWorkloads(ctx context.Context, workloads []kubectl.Workload) error {
	if n.config.SaasEndpoint == "" {
		return nil
	}

	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/workloads"

	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"trix_version": n.config.Version,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"workloads":    workloads,
	}

	if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
		return fmt.Errorf("saas workload sync failed: %w", err)
	}

	n.logger.Info("saas workloads sent", "count", len(workloads))
	return nil
}

// SendSaasScanFailures sends scan failure events to the SaaS backend.
// This enables alerting on failed Trivy scans (OOMKilled, etc.)
func (n *Notifier) SendSaasScanFailures(ctx context.Context, failures []trivy.ScanJob) error {
	if n.config.SaasEndpoint == "" {
		return nil
	}

	if len(failures) == 0 {
		return nil
	}

	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/scan-failures"

	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"trix_version": n.config.Version,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"failures":     failures,
	}

	if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
		return fmt.Errorf("saas scan failures sync failed: %w", err)
	}

	n.logger.Info("saas scan failures sent", "count", len(failures))
	return nil
}

// SendSaasExposure sends workload exposure analysis to the SaaS backend.
// This enables risk scoring based on network reachability.
func (n *Notifier) SendSaasExposure(ctx context.Context, exposures []kubectl.WorkloadExposure) error {
	if n.config.SaasEndpoint == "" {
		return nil
	}

	if len(exposures) == 0 {
		return nil
	}

	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/exposure"

	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"trix_version": n.config.Version,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"exposures":    exposures,
	}

	if err := n.postJSONWithAuth(ctx, url, payload); err != nil {
		return fmt.Errorf("saas exposure sync failed: %w", err)
	}

	n.logger.Info("saas exposure sent", "count", len(exposures))
	return nil
}

func (n *Notifier) postJSONWithAuth(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add API key authentication if configured
	if n.config.SaasApiKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.config.SaasApiKey)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	n.logger.Debug("saas notification sent", "url", url)
	return nil
}
