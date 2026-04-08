package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Checker orchestrates all diagnostic routines.
type Checker struct {
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
	namespace string
	enabled   map[string]bool
	timeout   time.Duration
	strict    bool
	apiCalls  *int64
	runtime   RuntimeOptions
}

type countingRoundTripper struct {
	next    http.RoundTripper
	counter *int64
}

type runtimeRoundTripper struct {
	next    http.RoundTripper
	counter *int64
	limiter chan struct{}
	retries int
	backoff time.Duration
}

func (c *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.counter != nil {
		atomic.AddInt64(c.counter, 1)
	}
	return c.next.RoundTrip(req)
}

func (r *runtimeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.limiter != nil {
		r.limiter <- struct{}{}
		defer func() { <-r.limiter }()
	}
	if r.counter != nil {
		atomic.AddInt64(r.counter, 1)
	}
	if req == nil || r.next == nil {
		return r.next.RoundTrip(req)
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return r.next.RoundTrip(req)
	}
	var (
		resp *http.Response
		err  error
	)
	for attempt := 0; attempt < r.retries; attempt++ {
		resp, err = r.next.RoundTrip(req.Clone(req.Context()))
		if err == nil && resp != nil && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}
		if resp != nil && (resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests) {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		} else if !isTransientError(err) {
			return resp, err
		}
		if attempt+1 < r.retries {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(time.Duration(attempt+1) * r.backoff):
			}
		}
	}
	return resp, err
}

func (c *Checker) Clientset() *kubernetes.Clientset {
	if c == nil {
		return nil
	}
	return c.clientset
}

func (c *Checker) NamespaceScope() string {
	if c == nil {
		return ""
	}
	return c.namespace
}

func (c *Checker) SetStrictCheckErrors(strict bool) {
	if c == nil {
		return
	}
	c.strict = strict
}

func (c *Checker) SetRuntimeOptions(options RuntimeOptions) {
	if c == nil {
		return
	}
	c.runtime = NormalizeRuntimeOptions(options)
}

func (c *Checker) APICallCount() int64 {
	if c == nil || c.apiCalls == nil {
		return 0
	}
	return atomic.LoadInt64(c.apiCalls)
}

// NewChecker builds a clientset using the provided kubeconfig and context name.
func NewChecker(kubeconfigPath, kubeContext, namespace string, enabled map[string]bool, timeout time.Duration) (*Checker, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build client config: %w", err)
	}

	// Keep API usage conservative for large clusters.
	config.QPS = 20
	config.Burst = 40
	runtimeOptions := NormalizeRuntimeOptions(RuntimeOptions{})

	apiCalls := int64(0)
	requestLimiter := make(chan struct{}, runtimeOptions.MaxConcurrentRequests)
	prevWrap := config.WrapTransport
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if prevWrap != nil {
			rt = prevWrap(rt)
		}
		return &runtimeRoundTripper{
			next:    rt,
			counter: &apiCalls,
			limiter: requestLimiter,
			retries: runtimeOptions.RetryAttempts,
			backoff: time.Duration(runtimeOptions.RetryInitialBackoffMS) * time.Millisecond,
		}
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}

	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}

	if len(enabled) == 0 {
		enabled = map[string]bool{
			"pods":            true,
			"gpu":             true,
			"runtimebehavior": true,
			"podsecurity":     true,
			"secrets":         true,
			"configexposure":  true,
			"networksecurity": true,
			"storagesecurity": true,
			"multitenancy":    true,
			"managedk8s":      true,
			"observability":   true,
			"policy":          true,
			"nodes":           true,
			"events":          true,
			"controllers":     true,
			"apiserver":       true,
			"rbac":            true,
			"serviceaccounts": true,
			"webhooks":        true,
			"cni":             true,
			"controlplane":    true,
			"dns":             true,
			"storage":         true,
			"certificates":    true,
			"quotas":          true,
			"ingress":         true,
			"autoscaling":     true,
			"pdb":             true,
			"scheduling":      true,
			"trends":          true,
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &Checker{clientset: cs, dynamic: dyn, namespace: namespace, enabled: enabled, timeout: timeout, apiCalls: &apiCalls, runtime: runtimeOptions}, nil
}

// Run executes all checks with a deadline and returns aggregated issues.
func (c *Checker) Run(ctx context.Context) ([]Issue, error) {
	result, err := c.RunDetailed(ctx)
	if err != nil {
		return nil, err
	}
	if c != nil && c.strict && result.FirstError != nil {
		return result.Issues, result.FirstError
	}
	return result.Issues, nil
}

// RunDetailed executes all checks with a deadline and records per-check execution details.
func (c *Checker) RunDetailed(ctx context.Context) (RunResult, error) {
	if c == nil || c.clientset == nil {
		return RunResult{}, errors.New("checker is not initialized")
	}
	c.runtime = NormalizeRuntimeOptions(c.runtime)

	startedAt := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	traceID := fmt.Sprintf("run-%d", startedAt.UnixNano())
	logger := newRuntimeLogger(c.runtime.LogFormat, traceID)
	ctx = withRuntimeContext(ctx, c.runtime, logger, traceID)
	logRuntimeEvent(ctx, "scan-start", map[string]any{"namespace": c.namespace, "checks": len(c.enabled)})

	// Default to all namespaces when not provided.
	ns := c.namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var (
		issues     []Issue
		executions []ExecutionRecord
		mu         sync.Mutex
		firstError error
	)
	preflight := collectCapabilityPreflight(ctx, c.clientset, c.namespace)

	add := func(found []Issue) {
		if len(found) == 0 {
			return
		}
		mu.Lock()
		issues = append(issues, found...)
		mu.Unlock()
	}
	addExecution := func(record ExecutionRecord) {
		mu.Lock()
		executions = append(executions, record)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	checkLimiter := make(chan struct{}, c.runtime.MaxConcurrentChecks)
	runCheck := func(name string, fn func(context.Context) ([]Issue, error)) {
		eg.Go(func() error {
			checkLimiter <- struct{}{}
			defer func() { <-checkLimiter }()
			start := time.Now()
			logRuntimeEvent(egCtx, "check-start", map[string]any{"check": name})
			found, err := fn(egCtx)
			status, code, permissionHint := ClassifyExecutionError(err)
			record := ExecutionRecord{
				Name:           name,
				Scope:          "check",
				Status:         status,
				DurationMS:     time.Since(start).Milliseconds(),
				IssueCount:     len(found),
				Slow:           operationIsSlow(egCtx, start),
				ErrorCode:      code,
				PermissionHint: permissionHint,
			}
			if err != nil {
				record.ErrorMessage = err.Error()
			}
			if err == nil {
				if len(found) > 0 {
					record.Status = ExecutionStatusFinding
				} else {
					record.Status = ExecutionStatusOK
				}
				add(found)
				addExecution(record)
				logRuntimeEvent(egCtx, "check-finish", map[string]any{"check": name, "status": record.Status, "issues": len(found), "durationMs": record.DurationMS, "slow": record.Slow})
				return nil
			}
			if len(found) > 0 {
				add(found)
				record.Status = ExecutionStatusPartial
			}
			if record.Status == ExecutionStatusError && firstError == nil {
				mu.Lock()
				if firstError == nil {
					firstError = fmt.Errorf("%s: %w", name, err)
				}
				mu.Unlock()
			}
			addExecution(record)
			logRuntimeEvent(egCtx, "check-finish", map[string]any{"check": name, "status": record.Status, "issues": len(found), "durationMs": record.DurationMS, "slow": record.Slow, "error": record.ErrorMessage})
			return nil
		})
	}
	if c.enabled["pods"] {
		runCheck("pods", func(runCtx context.Context) ([]Issue, error) { return CheckPods(runCtx, c.clientset, ns) })
	}
	if c.enabled["gpu"] {
		runCheck("gpu", func(runCtx context.Context) ([]Issue, error) { return CheckGPU(runCtx, c.clientset, c.dynamic, ns) })
	}
	if c.enabled["runtimebehavior"] {
		runCheck("runtimebehavior", func(runCtx context.Context) ([]Issue, error) { return CheckRuntimeBehavior(runCtx, c.clientset, ns) })
	}
	if c.enabled["podsecurity"] {
		runCheck("podsecurity", func(runCtx context.Context) ([]Issue, error) { return CheckPodSecurity(runCtx, c.clientset, ns) })
	}
	if c.enabled["secrets"] {
		runCheck("secrets", func(runCtx context.Context) ([]Issue, error) { return CheckSecrets(runCtx, c.clientset, ns) })
	}
	if c.enabled["configexposure"] {
		runCheck("configexposure", func(runCtx context.Context) ([]Issue, error) {
			return CheckConfigAndDataExposure(runCtx, c.clientset, ns)
		})
	}
	if c.enabled["networksecurity"] {
		runCheck("networksecurity", func(runCtx context.Context) ([]Issue, error) { return CheckNetworkSecurity(runCtx, c.clientset, ns) })
	}
	if c.enabled["storagesecurity"] {
		runCheck("storagesecurity", func(runCtx context.Context) ([]Issue, error) {
			return CheckStorageSecurity(runCtx, c.clientset, c.dynamic, ns)
		})
	}
	if c.enabled["multitenancy"] {
		runCheck("multitenancy", func(runCtx context.Context) ([]Issue, error) {
			return CheckMultiTenancy(runCtx, c.clientset, c.dynamic, ns)
		})
	}
	if c.enabled["managedk8s"] {
		runCheck("managedk8s", func(runCtx context.Context) ([]Issue, error) { return CheckManagedKubernetes(runCtx, c.clientset, ns) })
	}
	if c.enabled["observability"] {
		runCheck("observability", func(runCtx context.Context) ([]Issue, error) {
			return CheckObservabilityAndDetection(runCtx, c.clientset, c.dynamic, ns)
		})
	}
	if c.enabled["policy"] {
		runCheck("policy", func(runCtx context.Context) ([]Issue, error) { return CheckPolicyCompliance(runCtx, c.clientset, ns) })
	}
	if c.enabled["nodes"] {
		runCheck("nodes", func(runCtx context.Context) ([]Issue, error) { return CheckNodes(runCtx, c.clientset) })
	}
	if c.enabled["events"] {
		runCheck("events", func(runCtx context.Context) ([]Issue, error) { return CheckWarningEvents(runCtx, c.clientset, ns) })
	}
	if c.enabled["controllers"] {
		runCheck("controllers", func(runCtx context.Context) ([]Issue, error) { return CheckControllers(runCtx, c.clientset, ns) })
	}
	if c.enabled["apiserver"] {
		runCheck("apiserver", func(runCtx context.Context) ([]Issue, error) { return CheckAPIServerHealth(runCtx, c.clientset) })
	}
	if c.enabled["rbac"] {
		runCheck("rbac", func(runCtx context.Context) ([]Issue, error) { return CheckRBAC(runCtx, c.clientset, ns) })
	}
	if c.enabled["serviceaccounts"] {
		runCheck("serviceaccounts", func(runCtx context.Context) ([]Issue, error) {
			return CheckServiceAccountsAndTokens(runCtx, c.clientset, ns)
		})
	}
	if c.enabled["webhooks"] {
		runCheck("webhooks", func(runCtx context.Context) ([]Issue, error) { return CheckWebhooks(runCtx, c.clientset) })
	}
	if c.enabled["cni"] {
		runCheck("cni", func(runCtx context.Context) ([]Issue, error) { return CheckCNIAndCSI(runCtx, c.clientset) })
	}
	if c.enabled["controlplane"] {
		runCheck("controlplane", func(runCtx context.Context) ([]Issue, error) { return CheckControlPlane(runCtx, c.clientset) })
	}
	if c.enabled["dns"] {
		runCheck("dns", func(runCtx context.Context) ([]Issue, error) { return CheckDNS(runCtx, c.clientset) })
	}
	if c.enabled["storage"] {
		runCheck("storage", func(runCtx context.Context) ([]Issue, error) { return CheckStorage(runCtx, c.clientset, ns) })
	}
	if c.enabled["certificates"] {
		runCheck("certificates", func(runCtx context.Context) ([]Issue, error) { return CheckCertificates(runCtx, c.clientset, ns) })
	}
	if c.enabled["quotas"] {
		runCheck("quotas", func(runCtx context.Context) ([]Issue, error) { return CheckResourceQuotas(runCtx, c.clientset, ns) })
	}
	if c.enabled["ingress"] {
		runCheck("ingress", func(runCtx context.Context) ([]Issue, error) {
			return CheckIngresses(runCtx, c.clientset, c.dynamic, ns)
		})
	}
	if c.enabled["autoscaling"] {
		runCheck("autoscaling", func(runCtx context.Context) ([]Issue, error) { return CheckAutoscaling(runCtx, c.clientset, ns) })
	}
	if c.enabled["pdb"] {
		runCheck("pdb", func(runCtx context.Context) ([]Issue, error) { return CheckPDBs(runCtx, c.clientset, ns) })
	}
	if c.enabled["scheduling"] {
		runCheck("scheduling", func(runCtx context.Context) ([]Issue, error) { return CheckScheduling(runCtx, c.clientset, ns) })
	}
	if c.enabled["trends"] {
		runCheck("trends", func(runCtx context.Context) ([]Issue, error) { return CheckClusterTrends(runCtx, c.clientset, ns) })
	}

	_ = eg.Wait()

	finishedAt := time.Now().UTC()
	skipped := 0
	errored := 0
	slowChecks := 0
	for _, record := range executions {
		if record.Status == ExecutionStatusSkipped || record.Status == ExecutionStatusNotApplicable {
			skipped++
		}
		if record.Status == ExecutionStatusError || record.Status == ExecutionStatusPartial {
			errored++
		}
		if record.Slow {
			slowChecks++
		}
	}
	issues = NormalizeIssues(issues)
	runtimeStats := collectRuntimeStats()
	runtimeStats.SlowChecks = slowChecks

	result := RunResult{
		Issues: issues,
		Execution: ExecutionSummary{
			Status:        OverallExecutionStatus(executions),
			TraceID:       traceID,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
			DurationMS:    finishedAt.Sub(startedAt).Milliseconds(),
			APICalls:      c.APICallCount(),
			Runtime:       runtimeStats,
			Preflight:     preflight,
			Checks:        executions,
			SkippedChecks: skipped,
			ErroredChecks: errored,
		},
		FirstError: firstError,
	}
	logRuntimeEvent(ctx, "scan-finish", map[string]any{"status": result.Execution.Status, "durationMs": result.Execution.DurationMS, "apiCalls": result.Execution.APICalls, "slowChecks": slowChecks, "erroredChecks": errored})
	return result, nil
}

// DefaultKubeconfig tries to resolve a kubeconfig path similarly to kubectl.
func DefaultKubeconfig() string {
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s/.kube/config", home)
}
