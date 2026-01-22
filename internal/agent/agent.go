package agent

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

type Agent struct {
	config    *Config
	db        *DB
	poller    *Poller
	notifier  *Notifier
	logger    *slog.Logger
	ready     atomic.Bool
	firstPoll bool
}

func New(config *Config, logger *slog.Logger) (*Agent, error) {
	ctx := context.Background()

	db, err := NewDB(ctx, config.DatabasePath)
	if err != nil {
		return nil, err
	}

	poller, err := NewPoller(db, config, logger)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	notifier := NewNotifier(config, logger)

	return &Agent{
		config:    config,
		db:        db,
		poller:    poller,
		notifier:  notifier,
		logger:    logger,
		firstPoll: true,
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go a.runHealthServer(ctx)
	go a.runPollLoop(ctx)

	select {
	case sig := <-sigCh:
		a.logger.Info("received signal, shutting down", "signal", sig)
	case <-ctx.Done():
	}

	cancel()
	_ = a.db.Close()
	return nil
}

func (a *Agent) runHealthServer(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
		}
	})

	srv := &http.Server{
		Addr:    a.config.HealthAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	a.logger.Info("health server starting", "addr", a.config.HealthAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		a.logger.Error("health server error", "error", err)
	}
}

func (a *Agent) runPollLoop(ctx context.Context) {
	a.logger.Info("starting poll loop", "interval", a.config.PollInterval)

	// Initial poll
	a.poll(ctx)
	a.ready.Store(true)

	ticker := time.NewTicker(a.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.poll(ctx)
		}
	}
}

func (a *Agent) poll(ctx context.Context) {
	// Retry previously failed SaaS syncs BEFORE polling for new events.
	// This prevents double-sending: new events from Poll() would otherwise
	// be picked up by both retrySaasSync() AND SendSaas().
	if a.config.HasSaasEndpoint() {
		a.retrySaasSync(ctx)
	}

	events, err := a.poller.Poll(ctx)
	if err != nil {
		a.logger.Error("poll failed", "error", err)
		return
	}

	// Poll compliance benchmarks (CIS, NSA, PSS)
	a.pollCompliance(ctx)

	// Poll workload inventory for complete asset visibility
	a.pollWorkloads(ctx)

	// Poll for failed Trivy scan jobs (OOMKilled, etc.)
	a.pollScanFailures(ctx)

	// Poll for workload network exposure
	a.pollExposure(ctx)

	if !a.config.HasSaasEndpoint() {
		return
	}

	// Send vulnerability events to SaaS
	if len(events) > 0 {
		result := a.notifier.SendSaas(ctx, events)
		a.handleSaasResult(ctx, result)
	}
}

// pollWorkloads fetches and sends workload inventory to SaaS.
// This enables the platform to show all workloads, including those without vulnerabilities.
func (a *Agent) pollWorkloads(ctx context.Context) {
	if !a.config.HasSaasEndpoint() {
		return
	}

	workloads, err := a.poller.PollWorkloads(ctx)
	if err != nil {
		a.logger.Error("workload poll failed", "error", err)
		return
	}

	if len(workloads) > 0 {
		if err := a.notifier.SendSaasWorkloads(ctx, workloads); err != nil {
			a.logger.Error("workload sync failed", "error", err)
		}
	}
}

// pollScanFailures fetches and sends failed Trivy scan jobs to SaaS.
// This enables alerting on OOMKilled scans and other failures.
func (a *Agent) pollScanFailures(ctx context.Context) {
	if !a.config.HasSaasEndpoint() {
		return
	}

	failures, err := a.poller.PollScanFailures(ctx)
	if err != nil {
		a.logger.Error("scan failures poll failed", "error", err)
		return
	}

	if len(failures) > 0 {
		if err := a.notifier.SendSaasScanFailures(ctx, failures); err != nil {
			a.logger.Error("scan failures sync failed", "error", err)
		}
	}
}

// pollExposure fetches and sends workload network exposure analysis to SaaS.
// This enables risk scoring based on network reachability (internet-facing vs isolated).
func (a *Agent) pollExposure(ctx context.Context) {
	if !a.config.HasSaasEndpoint() {
		return
	}

	exposures, err := a.poller.PollExposure(ctx)
	if err != nil {
		a.logger.Error("exposure poll failed", "error", err)
		return
	}

	if len(exposures) > 0 {
		if err := a.notifier.SendSaasExposure(ctx, exposures); err != nil {
			a.logger.Error("exposure sync failed", "error", err)
		}
	}
}

// pollCompliance fetches and sends compliance benchmark results to SaaS.
func (a *Agent) pollCompliance(ctx context.Context) {
	if !a.config.HasSaasEndpoint() {
		return
	}

	// Send legacy summary compliance (backwards compat)
	compliance, err := a.poller.PollCompliance(ctx)
	if err != nil {
		a.logger.Error("compliance poll failed", "error", err)
		return
	}

	if len(compliance) > 0 {
		if err := a.notifier.SendSaasCompliance(ctx, compliance); err != nil {
			a.logger.Error("compliance sync failed", "error", err)
		}
	}

	// Send detailed compliance checks (new stateless sync)
	detailedChecks, err := a.poller.PollDetailedCompliance(ctx)
	if err != nil {
		a.logger.Error("detailed compliance poll failed", "error", err)
		return
	}

	if len(detailedChecks) > 0 {
		if err := a.notifier.SendSaasDetailedCompliance(ctx, detailedChecks); err != nil {
			a.logger.Error("detailed compliance sync failed", "error", err)
		}
	}
}

// handleSaasResult marks synced events in the database.
func (a *Agent) handleSaasResult(ctx context.Context, result *SaasResult) {
	if result == nil {
		return
	}

	if len(result.SyncedIDs) > 0 {
		if err := a.db.MarkSaasSynced(ctx, result.SyncedIDs); err != nil {
			a.logger.Error("failed to mark events as synced", "error", err)
		}
	}

	if result.Err != nil {
		a.logger.Error("saas sync had failures",
			"synced", len(result.SyncedIDs),
			"failed", len(result.FailedIDs),
			"error", result.Err,
		)
	} else if len(result.SyncedIDs) > 0 {
		a.logger.Info("saas sync complete", "synced", len(result.SyncedIDs))
	}
}

// retrySaasSync retries syncing events that previously failed.
func (a *Agent) retrySaasSync(ctx context.Context) {
	unsynced, err := a.db.GetUnsyncedVulnerabilities(ctx)
	if err != nil {
		a.logger.Error("failed to get unsynced vulnerabilities", "error", err)
		return
	}

	if len(unsynced) == 0 {
		return
	}

	a.logger.Info("retrying unsynced events", "count", len(unsynced))

	// Convert records to events
	events := make([]VulnerabilityEvent, 0, len(unsynced))
	for _, v := range unsynced {
		eventType := "NEW"
		if v.State == StateFixed {
			eventType = "FIXED"
		}
		events = append(events, VulnerabilityEvent{
			ID:              v.ID,
			Type:            eventType,
			CVE:             v.CVE,
			Workload:        v.Workload,
			Severity:        v.Severity,
			Image:           v.Image,
			ContainerName:   v.ContainerName,
			ImageRepository: v.ImageRepository,
			ImageTag:        v.ImageTag,
			ImageDigest:     v.ImageDigest,
			FixedVersion:    v.FixedVersion,
			FirstSeen:       v.FirstSeen,
			FixedAt:         v.FixedAt,
		})
	}

	result := a.notifier.SendSaas(ctx, events)
	a.handleSaasResult(ctx, result)
}
