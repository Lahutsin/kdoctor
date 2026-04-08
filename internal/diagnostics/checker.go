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

	return &Checker{clientset: cs, dynamic: dyn, namespace: namespace, enabled: enabled, timeout: timeout}, nil
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
	if c.enabled["gpu"] {
		eg.Go(func() error {
			gpuIssues, err := CheckGPU(egCtx, c.clientset, c.dynamic, ns)
			if err != nil {
				return fmt.Errorf("gpu: %w", err)
			}
			add(gpuIssues)
			return nil
		})
	}
	if c.enabled["runtimebehavior"] {
		eg.Go(func() error {
			runtimeIssues, err := CheckRuntimeBehavior(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("runtimebehavior: %w", err)
			}
			add(runtimeIssues)
			return nil
		})
	}
	if c.enabled["podsecurity"] {
		eg.Go(func() error {
			podSecurityIssues, err := CheckPodSecurity(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("podsecurity: %w", err)
			}
			add(podSecurityIssues)
			return nil
		})
	}
	if c.enabled["secrets"] {
		eg.Go(func() error {
			secretIssues, err := CheckSecrets(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			add(secretIssues)
			return nil
		})
	}
	if c.enabled["configexposure"] {
		eg.Go(func() error {
			configIssues, err := CheckConfigAndDataExposure(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("configexposure: %w", err)
			}
			add(configIssues)
			return nil
		})
	}
	if c.enabled["networksecurity"] {
		eg.Go(func() error {
			networkIssues, err := CheckNetworkSecurity(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("networksecurity: %w", err)
			}
			add(networkIssues)
			return nil
		})
	}
	if c.enabled["storagesecurity"] {
		eg.Go(func() error {
			storageSecurityIssues, err := CheckStorageSecurity(egCtx, c.clientset, c.dynamic, ns)
			if err != nil {
				return fmt.Errorf("storagesecurity: %w", err)
			}
			add(storageSecurityIssues)
			return nil
		})
	}
	if c.enabled["multitenancy"] {
		eg.Go(func() error {
			multitenancyIssues, err := CheckMultiTenancy(egCtx, c.clientset, c.dynamic, ns)
			if err != nil {
				return fmt.Errorf("multitenancy: %w", err)
			}
			add(multitenancyIssues)
			return nil
		})
	}
	if c.enabled["managedk8s"] {
		eg.Go(func() error {
			managedIssues, err := CheckManagedKubernetes(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("managedk8s: %w", err)
			}
			add(managedIssues)
			return nil
		})
	}
	if c.enabled["observability"] {
		eg.Go(func() error {
			observabilityIssues, err := CheckObservabilityAndDetection(egCtx, c.clientset, c.dynamic, ns)
			if err != nil {
				return fmt.Errorf("observability: %w", err)
			}
			add(observabilityIssues)
			return nil
		})
	}
	if c.enabled["policy"] {
		eg.Go(func() error {
			policyIssues, err := CheckPolicyCompliance(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("policy: %w", err)
			}
			add(policyIssues)
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
	if c.enabled["rbac"] {
		eg.Go(func() error {
			rbacIssues, err := CheckRBAC(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("rbac: %w", err)
			}
			add(rbacIssues)
			return nil
		})
	}
	if c.enabled["serviceaccounts"] {
		eg.Go(func() error {
			saIssues, err := CheckServiceAccountsAndTokens(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("serviceaccounts: %w", err)
			}
			add(saIssues)
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
	if c.enabled["dns"] {
		eg.Go(func() error {
			dnsIssues, err := CheckDNS(egCtx, c.clientset)
			if err != nil {
				return fmt.Errorf("dns: %w", err)
			}
			add(dnsIssues)
			return nil
		})
	}
	if c.enabled["storage"] {
		eg.Go(func() error {
			storageIssues, err := CheckStorage(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("storage: %w", err)
			}
			add(storageIssues)
			return nil
		})
	}
	if c.enabled["certificates"] {
		eg.Go(func() error {
			certIssues, err := CheckCertificates(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("certificates: %w", err)
			}
			add(certIssues)
			return nil
		})
	}
	if c.enabled["quotas"] {
		eg.Go(func() error {
			quotaIssues, err := CheckResourceQuotas(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("quotas: %w", err)
			}
			add(quotaIssues)
			return nil
		})
	}
	if c.enabled["ingress"] {
		eg.Go(func() error {
			ingressIssues, err := CheckIngresses(egCtx, c.clientset, c.dynamic, ns)
			if err != nil {
				return fmt.Errorf("ingress: %w", err)
			}
			add(ingressIssues)
			return nil
		})
	}
	if c.enabled["autoscaling"] {
		eg.Go(func() error {
			autoscalingIssues, err := CheckAutoscaling(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("autoscaling: %w", err)
			}
			add(autoscalingIssues)
			return nil
		})
	}
	if c.enabled["pdb"] {
		eg.Go(func() error {
			pdbIssues, err := CheckPDBs(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("pdb: %w", err)
			}
			add(pdbIssues)
			return nil
		})
	}
	if c.enabled["scheduling"] {
		eg.Go(func() error {
			schedulingIssues, err := CheckScheduling(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("scheduling: %w", err)
			}
			add(schedulingIssues)
			return nil
		})
	}
	if c.enabled["trends"] {
		eg.Go(func() error {
			trendIssues, err := CheckClusterTrends(egCtx, c.clientset, ns)
			if err != nil {
				return fmt.Errorf("trends: %w", err)
			}
			add(trendIssues)
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
