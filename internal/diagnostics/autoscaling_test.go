package diagnostics

import (
	"context"
	"net/http"
	"testing"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluateHPAConditions(t *testing.T) {
	issues := evaluateHPAConditions([]autoscalingv2.HorizontalPodAutoscalerCondition{
		{Type: autoscalingv2.ScalingLimited, Status: corev1.ConditionTrue, Message: "max replicas reached"},
		{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionFalse, Message: "metrics unavailable"},
	}, "prod", "web")
	if len(issues) != 2 {
		t.Fatalf("expected 2 condition issues, got %+v", issues)
	}
	if issues[0].Check != "hpa-scaling-limited" || issues[1].Check != "hpa-condition" {
		t.Fatalf("unexpected hpa condition checks: %+v", issues)
	}
}

func TestCheckAutoscaling(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/autoscaling/v2/namespaces/prod/horizontalpodautoscalers":
			minReplicas := int32(1)
			writeJSONResponse(t, w, http.StatusOK, &autoscalingv2.HorizontalPodAutoscalerList{Items: []autoscalingv2.HorizontalPodAutoscaler{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
				Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: &minReplicas},
				Status: autoscalingv2.HorizontalPodAutoscalerStatus{
					CurrentReplicas: 1,
					DesiredReplicas: 3,
					Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
						{Type: autoscalingv2.ScalingLimited, Status: corev1.ConditionTrue, Message: "max replicas reached"},
						{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse, Message: "controller syncing"},
					},
				},
			}}})
		case "/apis/autoscaling/v2/horizontalpodautoscalers":
			writeJSONResponse(t, w, http.StatusOK, &autoscalingv2.HorizontalPodAutoscalerList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckAutoscaling(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckAutoscaling returned error: %v", err)
	}
	if len(issues) != 4 {
		t.Fatalf("expected 4 autoscaling issues, got %+v", issues)
	}

	issues, err = CheckAutoscaling(ctx, cs, "")
	if err != nil {
		t.Fatalf("CheckAutoscaling all namespaces returned error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues for empty all-namespaces list, got %+v", issues)
	}
}
