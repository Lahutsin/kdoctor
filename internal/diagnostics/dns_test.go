package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckDNS(t *testing.T) {
	ctx := context.Background()

	missingCS := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/apps/v1/namespaces/kube-system/deployments" {
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{})
			return
		}
		writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	issues, err := CheckDNS(ctx, missingCS)
	if err != nil || len(issues) != 1 || issues[0].Check != "dns" {
		t.Fatalf("unexpected missing dns result: issues=%+v err=%v", issues, err)
	}

	pathTypeCS := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/kube-system/deployments":
			replicas := int32(2)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: metav1.NamespaceSystem}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{AvailableReplicas: 1}}}})
		case "/api/v1/namespaces/kube-system/services/kube-dns":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: metav1.NamespaceSystem}})
		case "/api/v1/namespaces/kube-system/endpoints/kube-dns":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Endpoints{})
		case "/api/v1/namespaces/kube-system/services/kube-dns/proxy":
			time.Sleep(1600 * time.Millisecond)
			_, _ = w.Write([]byte("ok"))
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err = CheckDNS(ctx, pathTypeCS)
	if err != nil || len(issues) < 3 {
		t.Fatalf("unexpected dns issues: issues=%+v err=%v", issues, err)
	}
}
