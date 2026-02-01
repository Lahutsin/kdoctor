package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Checker orchestrates all diagnostic routines.
type Checker struct {
	clientset *kubernetes.Clientset
	namespace string
	enabled   map[string]bool
	timeout   time.Duration
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

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}

	if len(enabled) == 0 {
		enabled = map[string]bool{
			"pods":         true,
			"nodes":        true,
			"events":       true,
			"controllers":  true,
			"apiserver":    true,
			"webhooks":     true,
			"cni":          true,
			"controlplane": true,
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &Checker{clientset: cs, namespace: namespace, enabled: enabled, timeout: timeout}, nil
}

// Run executes all checks with a deadline and returns aggregated issues.
func (c *Checker) Run(ctx context.Context) ([]Issue, error) {
	if c == nil || c.clientset == nil {
		return nil, errors.New("checker is not initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Default to all namespaces when not provided.
	ns := c.namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var (
		issues []Issue
		mu     sync.Mutex
	)

	add := func(found []Issue) {
		if len(found) == 0 {
			return
		}
		mu.Lock()
		issues = append(issues, found...)
		mu.Unlock()
	}

	eg, egCtx := errgroup.WithContext(ctx)
	if c.enabled["pods"] {
		eg.Go(func() error {
			podIssues, err := CheckPods(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("pods: %w", err)
			}
			add(podIssues)
			return nil
		})
	}
	if c.enabled["nodes"] {
		eg.Go(func() error {
			nodeIssues, err := CheckNodes(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("nodes: %w", err)
			}
			add(nodeIssues)
			return nil
		})
	}
	if c.enabled["events"] {
		eg.Go(func() error {
			eventIssues, err := CheckWarningEvents(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("events: %w", err)
			}
			add(eventIssues)
			return nil
		})
	}
	if c.enabled["controllers"] {
		eg.Go(func() error {
			controllerIssues, err := CheckControllers(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("controllers: %w", err)
			}
			add(controllerIssues)
			return nil
		})
	}
	if c.enabled["apiserver"] {
		eg.Go(func() error {
			apiIssues, err := CheckAPIServerHealth(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("apiserver: %w", err)
			}
			add(apiIssues)
			return nil
		})
	}
	if c.enabled["webhooks"] {
		eg.Go(func() error {
			whIssues, err := CheckWebhooks(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("webhooks: %w", err)
			}
			add(whIssues)
			return nil
		})
	}
	if c.enabled["cni"] {
		eg.Go(func() error {
			cniCSI, err := CheckCNIAndCSI(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("cni/csi: %w", err)
			}
			add(cniCSI)
			return nil
		})
	}
	if c.enabled["controlplane"] {
		eg.Go(func() error {
			controlPlane, err := CheckControlPlane(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("control-plane: %w", err)
			}
			add(controlPlane)
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return issues, nil
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
