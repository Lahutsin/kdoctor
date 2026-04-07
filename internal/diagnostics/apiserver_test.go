package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewAPIServerIssue(t *testing.T) {
	issue := newAPIServerIssue("readyz failed", SeverityCritical, "check control plane")
	if issue.Kind != "APIServer" || issue.Check != "apiserver" || issue.Category != "control-plane" {
		t.Fatalf("unexpected apiserver issue: %+v", issue)
	}
}

func TestCheckAPIServerHealthBranches(t *testing.T) {
	ctx := context.Background()
	baseHandler := func(t *testing.T, readyzStatus int, slow bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/readyz":
				if slow {
					time.Sleep(1600 * time.Millisecond)
				}
				w.WriteHeader(readyzStatus)
				_, _ = w.Write([]byte("ok"))
			case "/api/v1/namespaces/kube-public/configmaps/cluster-info":
				writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
			case "/api/v1/namespaces/default/services/kubernetes":
				writeJSONResponse(t, w, http.StatusOK, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1"}})
			case "/api/v1/nodes":
				writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{})
			case "/api/v1/secrets":
				writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{})
			case "/api/v1/configmaps":
				writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{})
			default:
				writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
			}
		}
	}

	slowCS := newHTTPBackedClientset(t, baseHandler(t, http.StatusOK, true))
	issues, err := CheckAPIServerHealth(ctx, slowCS)
	if err != nil {
		t.Fatalf("unexpected error for slow readyz: %v", err)
	}
	if len(issues) != 1 || issues[0].Severity != SeverityWarning {
		t.Fatalf("unexpected slow issues: %+v", issues)
	}

	failingCS := newHTTPBackedClientset(t, baseHandler(t, http.StatusInternalServerError, false))
	issues, err = CheckAPIServerHealth(ctx, failingCS)
	if err != nil {
		t.Fatalf("unexpected error for failing readyz request: %v", err)
	}
	if len(issues) == 0 || issues[0].Severity != SeverityCritical {
		t.Fatalf("expected critical issue for failing readyz, got %+v", issues)
	}

	if _, err := CheckAPIServerHealth(ctx, nil); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
