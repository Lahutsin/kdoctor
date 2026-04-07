package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSchedulingHelpersAndCheckScheduling(t *testing.T) {
	taint := corev1.Taint{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}
	if !toleratesTaint([]corev1.Toleration{{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}}, taint) {
		t.Fatal("expected exact taint toleration")
	}
	if !toleratesTaint([]corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}}, taint) {
		t.Fatal("expected exists toleration")
	}
	if len(untoleratedNodeTaints(nil, []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{taint}}}})) != 1 {
		t.Fatal("expected untolerated taint finding")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{Taints: []corev1.Taint{taint}}}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "prod"}, Status: corev1.PodStatus{Phase: corev1.PodPending}}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckScheduling(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckScheduling returned error: %v", err)
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 scheduling issue, got %+v", issues)
	}
}
