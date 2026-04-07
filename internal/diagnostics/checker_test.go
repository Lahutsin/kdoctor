package diagnostics

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

func TestCheckerHelpersAndRun(t *testing.T) {
	var nilChecker *Checker
	if nilChecker.Clientset() != nil || nilChecker.NamespaceScope() != "" {
		t.Fatal("expected nil checker helpers to return zero values")
	}
	if _, err := nilChecker.Run(context.Background()); err == nil {
		t.Fatal("expected nil checker run to fail")
	}

	checker := &Checker{clientset: newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(t, w, 404, map[string]string{"error": "not found"})
	}), namespace: "prod", enabled: map[string]bool{"noop": false}, timeout: time.Second}
	issues, err := checker.Run(context.Background())
	if err != nil {
		t.Fatalf("expected empty checker run to succeed, got %v", err)
	}
	if issues != nil {
		t.Fatalf("expected no issues, got %+v", issues)
	}
	if checker.NamespaceScope() != "prod" || checker.Clientset() == nil {
		t.Fatal("expected checker helpers to expose stored values")
	}
}

func TestCheckerRunWithManyEnabledChecks(t *testing.T) {
	checker := &Checker{
		clientset: newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}),
		namespace: "",
		timeout:   2 * time.Second,
		enabled: map[string]bool{
			"pods":            true,
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
		},
	}

	if _, err := checker.Run(context.Background()); err == nil {
		t.Fatal("expected checker run with generic failing backend to return an error")
	}
}

func TestDefaultKubeconfigAndNewChecker(t *testing.T) {
	old := os.Getenv("KUBECONFIG")
	defer func() {
		if old == "" {
			_ = os.Unsetenv("KUBECONFIG")
		} else {
			_ = os.Setenv("KUBECONFIG", old)
		}
	}()

	if err := os.Setenv("KUBECONFIG", "/tmp/custom-kubeconfig"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if DefaultKubeconfig() != "/tmp/custom-kubeconfig" {
		t.Fatalf("expected env kubeconfig path, got %q", DefaultKubeconfig())
	}
	_ = os.Unsetenv("KUBECONFIG")
	if fallback := DefaultKubeconfig(); filepath.Base(fallback) != "config" {
		t.Fatalf("expected kubeconfig fallback path, got %q", fallback)
	}

	if _, err := NewChecker("/definitely/missing", "", "", map[string]bool{"noop": false}, time.Second); err == nil {
		t.Fatal("expected invalid kubeconfig path to fail")
	}

	configPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(configPath, kubeconfigBytes(t, "http://127.0.0.1:65535", "reader", false), 0o644); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	if _, err := clientcmd.LoadFromFile(configPath); err != nil {
		t.Fatalf("expected kubeconfig to be readable: %v", err)
	}

	checker, err := NewChecker(configPath, "", "prod", nil, 0)
	if err != nil {
		t.Fatalf("NewChecker returned error: %v", err)
	}
	if checker.namespace != "prod" || checker.timeout != 30*time.Second {
		t.Fatalf("unexpected checker defaults: %+v", checker)
	}
	if !checker.enabled["pods"] || !checker.enabled["trends"] {
		t.Fatalf("expected default checks to be enabled, got %+v", checker.enabled)
	}
}
