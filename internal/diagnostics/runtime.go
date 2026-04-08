package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
)

const ReportSchemaVersion = "v1alpha2"

type RuntimeOptions struct {
	ListChunkSize          int    `json:"listChunkSize,omitempty"`
	MaxListItems           int    `json:"maxListItems,omitempty"`
	MaxConcurrentChecks    int    `json:"maxConcurrentChecks,omitempty"`
	MaxConcurrentRequests  int    `json:"maxConcurrentRequests,omitempty"`
	RetryAttempts          int    `json:"retryAttempts,omitempty"`
	RetryInitialBackoffMS  int    `json:"retryInitialBackoffMs,omitempty"`
	SlowOperationThreshold int64  `json:"slowOperationThresholdMs,omitempty"`
	LogFormat              string `json:"logFormat,omitempty"`
}

type CapabilityCheck struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace,omitempty"`
	Verb         string `json:"verb,omitempty"`
	Resource     string `json:"resource,omitempty"`
	Allowed      bool   `json:"allowed"`
	Reason       string `json:"reason,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

type CapabilitySummary struct {
	Status ExecutionStatus   `json:"status"`
	Checks []CapabilityCheck `json:"checks,omitempty"`
}

type RuntimeStats struct {
	MemoryAllocBytes uint64 `json:"memoryAllocBytes,omitempty"`
	TotalAllocBytes  uint64 `json:"totalAllocBytes,omitempty"`
	SysBytes         uint64 `json:"sysBytes,omitempty"`
	NumGC            uint32 `json:"numGC,omitempty"`
	SlowChecks       int    `json:"slowChecks,omitempty"`
	SlowSections     int    `json:"slowSections,omitempty"`
}

type runtimeContextKey struct{}

type runtimeContext struct {
	options RuntimeOptions
	cache   *resourceCache
	logger  *runtimeLogger
	traceID string
}

type runtimeLogger struct {
	mu      sync.Mutex
	out     io.Writer
	format  string
	traceID string
}

type resourceCache struct {
	mu                           sync.Mutex
	pods                         map[string][]corev1.Pod
	events                       map[string][]corev1.Event
	serviceAccounts              map[string][]corev1.ServiceAccount
	services                     map[string][]corev1.Service
	endpoints                    map[string][]corev1.Endpoints
	secrets                      map[string][]corev1.Secret
	ingresses                    map[string][]networkingv1.Ingress
	roles                        map[string][]rbacv1.Role
	roleBindings                 map[string][]rbacv1.RoleBinding
	daemonSets                   map[string][]appsv1.DaemonSet
	cronJobs                     map[string][]batchv1.CronJob
	configMaps                   map[string][]corev1.ConfigMap
	validatingWebhookConfigs     []admissionv1.ValidatingWebhookConfiguration
	mutatingWebhookConfigs       []admissionv1.MutatingWebhookConfiguration
	clusterRoleBindings          []rbacv1.ClusterRoleBinding
	clusterRoles                 []rbacv1.ClusterRole
	nodes                        []corev1.Node
	namespaces                   []corev1.Namespace
	namespaceMetaByScope         map[string]map[string]namespaceMeta
	validatingWebhookConfigsDone bool
	mutatingWebhookConfigsDone   bool
	clusterRoleBindingsDone      bool
	clusterRolesDone             bool
	nodesDone                    bool
	namespacesDone               bool
}

func defaultRuntimeOptions() RuntimeOptions {
	return RuntimeOptions{
		ListChunkSize:          250,
		MaxListItems:           50000,
		MaxConcurrentChecks:    4,
		MaxConcurrentRequests:  8,
		RetryAttempts:          3,
		RetryInitialBackoffMS:  200,
		SlowOperationThreshold: 1500,
		LogFormat:              "off",
	}
}

func NormalizeRuntimeOptions(options RuntimeOptions) RuntimeOptions {
	defaults := defaultRuntimeOptions()
	if options.ListChunkSize <= 0 {
		options.ListChunkSize = defaults.ListChunkSize
	}
	if options.MaxListItems <= 0 {
		options.MaxListItems = defaults.MaxListItems
	}
	if options.MaxConcurrentChecks <= 0 {
		options.MaxConcurrentChecks = defaults.MaxConcurrentChecks
	}
	if options.MaxConcurrentRequests <= 0 {
		options.MaxConcurrentRequests = defaults.MaxConcurrentRequests
	}
	if options.RetryAttempts <= 0 {
		options.RetryAttempts = defaults.RetryAttempts
	}
	if options.RetryInitialBackoffMS <= 0 {
		options.RetryInitialBackoffMS = defaults.RetryInitialBackoffMS
	}
	if options.SlowOperationThreshold <= 0 {
		options.SlowOperationThreshold = defaults.SlowOperationThreshold
	}
	options.LogFormat = strings.ToLower(strings.TrimSpace(options.LogFormat))
	if options.LogFormat == "" {
		options.LogFormat = defaults.LogFormat
	}
	switch options.LogFormat {
	case "off", "text", "json":
	default:
		options.LogFormat = defaults.LogFormat
	}
	return options
}

func newRuntimeLogger(format, traceID string) *runtimeLogger {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "off"
	}
	return &runtimeLogger{out: os.Stderr, format: format, traceID: traceID}
}

func (l *runtimeLogger) Log(event string, fields map[string]any) {
	if l == nil || l.format == "off" {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	fields["traceId"] = l.traceID
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)

	l.mu.Lock()
	defer l.mu.Unlock()

	switch l.format {
	case "json":
		data, err := json.Marshal(fields)
		if err == nil {
			_, _ = fmt.Fprintln(l.out, string(data))
		}
	default:
		parts := make([]string, 0, len(fields))
		for key, value := range fields {
			if key == "event" || key == "traceId" || key == "ts" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%v", key, value))
		}
		_, _ = fmt.Fprintf(l.out, "%s traceId=%s event=%s %s\n", fields["ts"], l.traceID, event, strings.Join(parts, " "))
	}
}

func newResourceCache() *resourceCache {
	return &resourceCache{
		pods:                 map[string][]corev1.Pod{},
		events:               map[string][]corev1.Event{},
		serviceAccounts:      map[string][]corev1.ServiceAccount{},
		services:             map[string][]corev1.Service{},
		endpoints:            map[string][]corev1.Endpoints{},
		secrets:              map[string][]corev1.Secret{},
		ingresses:            map[string][]networkingv1.Ingress{},
		roles:                map[string][]rbacv1.Role{},
		roleBindings:         map[string][]rbacv1.RoleBinding{},
		daemonSets:           map[string][]appsv1.DaemonSet{},
		cronJobs:             map[string][]batchv1.CronJob{},
		configMaps:           map[string][]corev1.ConfigMap{},
		namespaceMetaByScope: map[string]map[string]namespaceMeta{},
	}
}

func withRuntimeContext(ctx context.Context, options RuntimeOptions, logger *runtimeLogger, traceID string) context.Context {
	return context.WithValue(ctx, runtimeContextKey{}, &runtimeContext{
		options: NormalizeRuntimeOptions(options),
		cache:   newResourceCache(),
		logger:  logger,
		traceID: traceID,
	})
}

func runtimeStateFromContext(ctx context.Context) *runtimeContext {
	state, _ := ctx.Value(runtimeContextKey{}).(*runtimeContext)
	if state == nil {
		defaults := defaultRuntimeOptions()
		state = &runtimeContext{
			options: defaults,
			cache:   newResourceCache(),
			logger:  newRuntimeLogger(defaults.LogFormat, "local"),
			traceID: "local",
		}
	}
	return state
}

func runtimeOptionsFromContext(ctx context.Context) RuntimeOptions {
	return runtimeStateFromContext(ctx).options
}

func runtimeTraceID(ctx context.Context) string {
	return runtimeStateFromContext(ctx).traceID
}

func logRuntimeEvent(ctx context.Context, event string, fields map[string]any) {
	runtimeStateFromContext(ctx).logger.Log(event, fields)
}

func operationIsSlow(ctx context.Context, started time.Time) bool {
	return time.Since(started).Milliseconds() >= runtimeOptionsFromContext(ctx).SlowOperationThreshold
}

func collectRuntimeStats() RuntimeStats {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return RuntimeStats{
		MemoryAllocBytes: mem.Alloc,
		TotalAllocBytes:  mem.TotalAlloc,
		SysBytes:         mem.Sys,
		NumGC:            mem.NumGC,
	}
}

func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsTooManyRequests(err) || apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"connection reset", "connection refused", "eof", "tls handshake timeout", "server closed idle connection", "temporarily unavailable", "i/o timeout"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func withRetry(ctx context.Context, operation string, fn func() error) error {
	options := runtimeOptionsFromContext(ctx)
	backoff := wait.Backoff{
		Duration: time.Duration(options.RetryInitialBackoffMS) * time.Millisecond,
		Factor:   2,
		Jitter:   0.1,
		Steps:    options.RetryAttempts,
	}
	var lastErr error
	err := retry.OnError(backoff, isTransientError, func() error {
		lastErr = fn()
		if lastErr != nil && isTransientError(lastErr) {
			logRuntimeEvent(ctx, "retry", map[string]any{"operation": operation, "error": lastErr.Error()})
		}
		return lastErr
	})
	if err != nil {
		return err
	}
	return lastErr
}

func pagedList[T any](ctx context.Context, resource string, page func(metav1.ListOptions) ([]T, string, error)) ([]T, error) {
	options := runtimeOptionsFromContext(ctx)
	var (
		all           []T
		continueToken string
	)
	for {
		listOptions := metav1.ListOptions{Continue: continueToken}
		if options.ListChunkSize > 0 {
			listOptions.Limit = int64(options.ListChunkSize)
		}
		var (
			items []T
			next  string
		)
		if err := withRetry(ctx, resource, func() error {
			var err error
			items, next, err = page(listOptions)
			return err
		}); err != nil {
			return nil, err
		}
		all = append(all, items...)
		if options.MaxListItems > 0 && len(all) > options.MaxListItems {
			return nil, fmt.Errorf("%s list exceeded memory guardrail of %d items", resource, options.MaxListItems)
		}
		if next == "" {
			break
		}
		continueToken = next
	}
	return all, nil
}

func cloneSlice[T any](items []T) []T {
	if len(items) == 0 {
		return nil
	}
	return append([]T(nil), items...)
}

func listPodsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.Pod, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.pods[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("pods[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.Pod, string, error) {
		list, err := cs.CoreV1().Pods(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.pods[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listEventsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.Event, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.events[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("events[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.Event, string, error) {
		list, err := cs.CoreV1().Events(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.events[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listNodesCached(ctx context.Context, cs *kubernetes.Clientset) ([]corev1.Node, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.nodesDone {
		items := cloneSlice(state.cache.nodes)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "nodes", func(opts metav1.ListOptions) ([]corev1.Node, string, error) {
		list, err := cs.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.nodes = cloneSlice(items)
	state.cache.nodesDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listDaemonSetsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]appsv1.DaemonSet, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.daemonSets[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("daemonsets[%s]", namespace), func(opts metav1.ListOptions) ([]appsv1.DaemonSet, string, error) {
		list, err := cs.AppsV1().DaemonSets(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.daemonSets[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listConfigMapsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.ConfigMap, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.configMaps[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("configmaps[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.ConfigMap, string, error) {
		list, err := cs.CoreV1().ConfigMaps(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.configMaps[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listServiceAccountsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.ServiceAccount, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.serviceAccounts[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("serviceaccounts[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.ServiceAccount, string, error) {
		list, err := cs.CoreV1().ServiceAccounts(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.serviceAccounts[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listServicesCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.Service, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.services[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("services[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.Service, string, error) {
		list, err := cs.CoreV1().Services(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.services[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listEndpointsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.Endpoints, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.endpoints[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("endpoints[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.Endpoints, string, error) {
		list, err := cs.CoreV1().Endpoints(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.endpoints[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listSecretsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]corev1.Secret, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.secrets[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("secrets[%s]", namespace), func(opts metav1.ListOptions) ([]corev1.Secret, string, error) {
		list, err := cs.CoreV1().Secrets(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.secrets[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listIngressesCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]networkingv1.Ingress, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.ingresses[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("ingresses[%s]", namespace), func(opts metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
		list, err := cs.NetworkingV1().Ingresses(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.ingresses[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listCronJobsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]batchv1.CronJob, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.cronJobs[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("cronjobs[%s]", namespace), func(opts metav1.ListOptions) ([]batchv1.CronJob, string, error) {
		list, err := cs.BatchV1().CronJobs(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.cronJobs[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listRolesCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]rbacv1.Role, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.roles[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("roles[%s]", namespace), func(opts metav1.ListOptions) ([]rbacv1.Role, string, error) {
		list, err := cs.RbacV1().Roles(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.roles[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listClusterRolesCached(ctx context.Context, cs *kubernetes.Clientset) ([]rbacv1.ClusterRole, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.clusterRolesDone {
		items := cloneSlice(state.cache.clusterRoles)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "clusterroles", func(opts metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
		list, err := cs.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.clusterRoles = cloneSlice(items)
	state.cache.clusterRolesDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listRoleBindingsCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]rbacv1.RoleBinding, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if items, ok := state.cache.roleBindings[namespace]; ok {
		state.cache.mu.Unlock()
		return cloneSlice(items), nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, fmt.Sprintf("rolebindings[%s]", namespace), func(opts metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
		list, err := cs.RbacV1().RoleBindings(namespace).List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.roleBindings[namespace] = cloneSlice(items)
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listClusterRoleBindingsCached(ctx context.Context, cs *kubernetes.Clientset) ([]rbacv1.ClusterRoleBinding, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.clusterRoleBindingsDone {
		items := cloneSlice(state.cache.clusterRoleBindings)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "clusterrolebindings", func(opts metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
		list, err := cs.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.clusterRoleBindings = cloneSlice(items)
	state.cache.clusterRoleBindingsDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listNamespacesCached(ctx context.Context, cs *kubernetes.Clientset) ([]corev1.Namespace, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.namespacesDone {
		items := cloneSlice(state.cache.namespaces)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "namespaces", func(opts metav1.ListOptions) ([]corev1.Namespace, string, error) {
		list, err := cs.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.namespaces = cloneSlice(items)
	state.cache.namespacesDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func getNamespaceCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) (*corev1.Namespace, error) {
	namespaces, err := listNamespacesCached(ctx, cs)
	if err != nil {
		return nil, err
	}
	for _, ns := range namespaces {
		if ns.Name == namespace {
			copy := ns
			return &copy, nil
		}
	}
	return nil, apierrors.NewNotFound(corev1.Resource("namespaces"), namespace)
}

func listValidatingWebhookConfigurationsCached(ctx context.Context, cs *kubernetes.Clientset) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.validatingWebhookConfigsDone {
		items := cloneSlice(state.cache.validatingWebhookConfigs)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "validatingwebhookconfigurations", func(opts metav1.ListOptions) ([]admissionv1.ValidatingWebhookConfiguration, string, error) {
		list, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.validatingWebhookConfigs = cloneSlice(items)
	state.cache.validatingWebhookConfigsDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listMutatingWebhookConfigurationsCached(ctx context.Context, cs *kubernetes.Clientset) ([]admissionv1.MutatingWebhookConfiguration, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if state.cache.mutatingWebhookConfigsDone {
		items := cloneSlice(state.cache.mutatingWebhookConfigs)
		state.cache.mu.Unlock()
		return items, nil
	}
	state.cache.mu.Unlock()
	items, err := pagedList(ctx, "mutatingwebhookconfigurations", func(opts metav1.ListOptions) ([]admissionv1.MutatingWebhookConfiguration, string, error) {
		list, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, opts)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	state.cache.mu.Lock()
	state.cache.mutatingWebhookConfigs = cloneSlice(items)
	state.cache.mutatingWebhookConfigsDone = true
	state.cache.mu.Unlock()
	return cloneSlice(items), nil
}

func listNamespaceMetaCached(ctx context.Context, cs *kubernetes.Clientset, namespace string) (map[string]namespaceMeta, error) {
	state := runtimeStateFromContext(ctx)
	state.cache.mu.Lock()
	if cached, ok := state.cache.namespaceMetaByScope[namespace]; ok {
		result := make(map[string]namespaceMeta, len(cached))
		for key, value := range cached {
			result[key] = value
		}
		state.cache.mu.Unlock()
		return result, nil
	}
	state.cache.mu.Unlock()

	result := make(map[string]namespaceMeta)
	if namespace != "" {
		ns, err := getNamespaceCached(ctx, cs, namespace)
		if err != nil {
			if apierrors.IsNotFound(err) {
				result[namespace] = namespaceMeta{name: namespace, labels: map[string]string{}, annotations: map[string]string{}}
			} else {
				return nil, err
			}
		} else {
			result[ns.Name] = namespaceMeta{name: ns.Name, labels: ns.Labels, annotations: ns.Annotations}
		}
	} else {
		namespaces, err := listNamespacesCached(ctx, cs)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return nil, err
			}
			namespaces = nil
		}
		for _, ns := range namespaces {
			result[ns.Name] = namespaceMeta{name: ns.Name, labels: ns.Labels, annotations: ns.Annotations}
		}
	}

	state.cache.mu.Lock()
	state.cache.namespaceMetaByScope[namespace] = result
	state.cache.mu.Unlock()
	copyResult := make(map[string]namespaceMeta, len(result))
	for key, value := range result {
		copyResult[key] = value
	}
	return copyResult, nil
}

func collectCapabilityPreflight(ctx context.Context, cs *kubernetes.Clientset, namespace string) CapabilitySummary {
	checks := []CapabilityCheck{}
	scopeNamespace := namespace
	if scopeNamespace == "" {
		scopeNamespace = metav1.NamespaceDefault
	}
	for _, spec := range []struct {
		name      string
		namespace string
		verb      string
		group     string
		resource  string
	}{
		{name: "list-pods", namespace: scopeNamespace, verb: "list", resource: "pods"},
		{name: "list-events", namespace: scopeNamespace, verb: "list", resource: "events"},
		{name: "list-secrets", namespace: scopeNamespace, verb: "list", resource: "secrets"},
		{name: "list-serviceaccounts", namespace: scopeNamespace, verb: "list", resource: "serviceaccounts"},
		{name: "list-nodes", verb: "list", resource: "nodes"},
		{name: "list-namespaces", verb: "list", resource: "namespaces"},
		{name: "list-validating-webhooks", verb: "list", group: "admissionregistration.k8s.io", resource: "validatingwebhookconfigurations"},
		{name: "list-mutating-webhooks", verb: "list", group: "admissionregistration.k8s.io", resource: "mutatingwebhookconfigurations"},
		{name: "create-selfsubjectaccessreviews", verb: "create", group: "authorization.k8s.io", resource: "selfsubjectaccessreviews"},
	} {
		check := CapabilityCheck{Name: spec.name, Namespace: spec.namespace, Verb: spec.verb, Resource: spec.resource}
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: spec.namespace,
					Verb:      spec.verb,
					Group:     spec.group,
					Resource:  spec.resource,
				},
			},
		}
		var response *authorizationv1.SelfSubjectAccessReview
		err := withRetry(ctx, "rbac-preflight:"+spec.name, func() error {
			var err error
			response, err = cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
			return err
		})
		if err != nil {
			check.Reason = "unavailable"
			check.ErrorMessage = err.Error()
			checks = append(checks, check)
			continue
		}
		check.Allowed = response.Status.Allowed
		check.Reason = response.Status.Reason
		if response.Status.EvaluationError != "" {
			check.ErrorMessage = response.Status.EvaluationError
		}
		checks = append(checks, check)
	}
	status := ExecutionStatusOK
	for _, check := range checks {
		if check.ErrorMessage != "" && !check.Allowed {
			status = ExecutionStatusPartial
			continue
		}
		if !check.Allowed && status == ExecutionStatusOK {
			status = ExecutionStatusPartial
		}
	}
	return CapabilitySummary{Status: status, Checks: checks}
}

func ptrBool(value bool) *bool {
	return ptr.To(value)
}
