package diagnostics

import (
	"context"
	"net/http"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestObservabilityHelpersAndCheckObservabilityAndDetection(t *testing.T) {
	if !hasMonitoringStack([]appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "prometheus", Namespace: "monitoring"}}}, nil) {
		t.Fatal("expected monitoring stack detection")
	}
	if !workloadSetContains([]corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "falco-a", Namespace: "security"}}}, nil, []string{"falco"}) {
		t.Fatal("expected workload marker detection in pods")
	}
	if !workloadSetContainsPodsAndDeployments(nil, []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "argocd", Namespace: "argocd"}}}, []string{"argocd"}) {
		t.Fatal("expected workload marker detection in deployments")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{})
		case "/apis/apps/v1/deployments":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "prometheus", Namespace: "monitoring"}}}})
		case "/apis/apps/v1/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{})
		case "/api/v1/configmaps":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{})
		case "/api/v1/namespaces/kube-system/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-a", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-apiserver"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--secure-port=6443"}}}},
			}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckObservabilityAndDetection(ctx, cs, nil, "")
	if err != nil {
		t.Fatalf("CheckObservabilityAndDetection returned error: %v", err)
	}
	if len(issues) < 7 {
		t.Fatalf("expected several observability issues, got %+v", issues)
	}

	issues, err = CheckObservabilityAndDetection(ctx, cs, nil, "prod")
	if err != nil || issues != nil {
		t.Fatalf("expected namespaced check to return nil,nil, got issues=%+v err=%v", issues, err)
	}
}

func TestCollectAlertRuleCorpusAndHelperBranches(t *testing.T) {
	rule := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "monitoring.coreos.com/v1",
		"kind":       "PrometheusRule",
		"metadata": map[string]any{
			"name":      "rbac-alerts",
			"namespace": "monitoring",
		},
		"spec": map[string]any{
			"groups": []any{map[string]any{"name": "security", "rules": []any{map[string]any{"alert": "RBACDrift", "expr": "clusterrolebinding"}}}},
		},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{prometheusRuleGVR: "PrometheusRuleList"},
		rule,
	)
	corpus := collectAlertRuleCorpus(context.Background(), dyn, "monitoring", []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "alert-rules"}, Data: map[string]string{"rules": "secret access"}}})
	if !containsAny(corpus, []string{"rbacdrift", "secret access", "clusterrolebinding"}) {
		t.Fatalf("unexpected alert rule corpus: %q", corpus)
	}
	issues := alertCoverageIssues([]appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "prometheus", Namespace: "monitoring"}}}, nil, corpus)
	if len(issues) != 3 {
		t.Fatalf("expected 3 remaining alert coverage gaps, got %+v", issues)
	}
}
