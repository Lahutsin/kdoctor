package diagnostics

import (
	"context"
	"net/http"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyComplianceHelpersAndCheckPolicyCompliance(t *testing.T) {
	replicas := int32(3)
	namespaces := map[string]namespaceMeta{
		"prod": {name: "prod", labels: map[string]string{"environment": "production"}},
		"dev":  {name: "dev", annotations: map[string]string{"security-exception": "yes"}},
	}
	dep := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}},
	}
	sts := appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}}},
	}
	ds := appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "prod", Annotations: map[string]string{"exception": "true"}}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "prod", Labels: map[string]string{"app": "api"}, Annotations: map[string]string{"security-exception": "yes"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api",
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("0")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("0")},
			},
		}}},
	}

	if !hasExceptionMarkers(map[string]string{"security-exception": "yes"}, nil) || hasExceptionMetadata(nil, map[string]string{"reason": "x"}) {
		t.Fatal("unexpected exception metadata helpers")
	}
	if hasRequiredOwnershipMetadata(nil, nil) || !hasMetadataKey(nil, map[string]string{"owner": "team-a"}, []string{"owner"}) {
		t.Fatal("unexpected ownership metadata helpers")
	}
	if len(requiredMetadataIssues(namespaces, []appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []appsv1.DaemonSet{ds})) == 0 {
		t.Fatal("expected required metadata issues")
	}
	if len(mandatorySecurityContextIssues([]corev1.Pod{pod}, namespaces)) == 0 {
		t.Fatal("expected mandatory security context issue")
	}
	if len(mandatoryNetworkPolicyIssues([]corev1.Pod{pod}, namespaces, nil)) == 0 {
		t.Fatal("expected mandatory network policy issue")
	}
	if !controllerNeedsPDB("prod", "api", &replicas, map[string]string{"app": "api"}, namespaces, nil) || len(mandatoryPDBIssues([]appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, nil, namespaces)) == 0 {
		t.Fatal("expected PDB requirement issues")
	}
	if len(mandatoryResourceRequestsIssues([]corev1.Pod{pod}, namespaces)) == 0 {
		t.Fatal("expected resource request policy issue")
	}
	if len(controllerExceptionIssues([]appsv1.Deployment{dep}, []appsv1.StatefulSet{sts}, []appsv1.DaemonSet{ds})) == 0 {
		t.Fatal("expected controller exception issue")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/apis/apps/v1/namespaces/prod/deployments":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{dep}})
		case "/apis/apps/v1/namespaces/prod/statefulsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.StatefulSetList{Items: []appsv1.StatefulSet{sts}})
		case "/apis/apps/v1/namespaces/prod/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{ds}})
		case "/apis/policy/v1/namespaces/prod/poddisruptionbudgets":
			writeJSONResponse(t, w, http.StatusOK, &policyv1.PodDisruptionBudgetList{})
		case "/apis/networking.k8s.io/v1/namespaces/prod/networkpolicies":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.NetworkPolicyList{})
		case "/metrics":
			_, _ = w.Write([]byte("apiserver_requested_deprecated_apis{group=\"extensions\",version=\"v1beta1\",resource=\"ingresses\"} 1\n"))
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckPolicyCompliance(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckPolicyCompliance returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected several policy compliance issues, got %+v", issues)
	}
	if _, err := CheckPolicyCompliance(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
