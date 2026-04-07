package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControlPlaneHelpers(t *testing.T) {
	if value, ok := parsePromGauge("workqueue_depth 123"); !ok || value != 123 {
		t.Fatalf("unexpected prom gauge parse: value=%v ok=%v", value, ok)
	}
	if _, ok := parsePromGauge("broken"); ok {
		t.Fatal("expected invalid gauge parse to fail")
	}
	if !isPodReady(&corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}) {
		t.Fatal("expected ready pod")
	}
	if isPodReady(nil) || len(parseSchedulerMetrics([]byte("scheduler_pending_pods 0\n"))) != 0 {
		t.Fatal("unexpected helper result")
	}
	if len(parseSchedulerMetrics([]byte("scheduler_pending_pods 2\n"))) != 1 {
		t.Fatal("expected scheduler issue")
	}
	if len(parseControllerManagerMetrics([]byte("workqueue_depth 101\n"))) != 1 {
		t.Fatal("expected controller-manager metric issue")
	}
	issue := issueFromComponent("kube-scheduler", SeverityWarning, "summary", "rec")
	if issue.Check != "controlplane-metrics" || issue.Category != "control-plane" {
		t.Fatalf("unexpected controlplane issue helper: %+v", issue)
	}
}

func TestCheckControlPlane(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/livez/etcd":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case "/metrics":
			_, _ = w.Write([]byte("etcd_mvcc_db_total_size_in_bytes 2147483648\n"))
		case "/api/v1/namespaces/kube-system/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "sched-0", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-scheduler"}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "cm-0", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-controller-manager"}}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}},
			}})
		case "/api/v1/namespaces/kube-system/pods/sched-0/proxy/metrics":
			_, _ = w.Write([]byte("scheduler_pending_pods 3\n"))
		case "/api/v1/namespaces/kube-system/pods/cm-0/proxy/metrics":
			_, _ = w.Write([]byte("workqueue_depth 200\n"))
		case "/api/v1/namespaces/kube-system/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{})
		case "/apis/certificates.k8s.io/v1/certificatesigningrequests":
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"kind": "CertificateSigningRequestList", "apiVersion": "certificates.k8s.io/v1", "items": []any{}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issue := probeEtcd(ctx, cs)
	if issue == nil || issue.Check != "etcd-size" {
		t.Fatalf("expected etcd size issue, got %+v", issue)
	}
	issues, err := checkComponentPods(ctx, cs, "kube-scheduler")
	if err != nil || len(issues) < 2 {
		t.Fatalf("unexpected scheduler component issues: issues=%+v err=%v", issues, err)
	}
	issues, err = CheckControlPlane(ctx, cs)
	if err != nil || len(issues) < 4 {
		t.Fatalf("unexpected controlplane issues: issues=%+v err=%v", issues, err)
	}
	if _, err := CheckControlPlane(ctx, nil); err == nil {
		t.Fatal("expected nil clientset to fail")
	}

	skipCS := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/livez/etcd":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	if got := probeEtcd(ctx, skipCS); got != nil {
		t.Fatalf("expected nil etcd issue on 404 livez, got %+v", got)
	}

	slowCS := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/livez/etcd" {
			time.Sleep(800 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	if got := probeEtcd(ctx, slowCS); got == nil || got.Check != "etcd-latency" {
		t.Fatalf("expected latency issue, got %+v", got)
	}
}
