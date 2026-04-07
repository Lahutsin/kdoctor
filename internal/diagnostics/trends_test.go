package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckClusterTrends(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: []corev1.Event{
			{Reason: "Preempted", Count: 3, LastTimestamp: metav1.NewTime(now)},
			{Reason: "Evicted", Count: 3, LastTimestamp: metav1.NewTime(now.Add(-5 * time.Minute))},
			{Reason: "Evicted", Count: 10, LastTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))},
		}})
	})

	issues, err := CheckClusterTrends(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckClusterTrends returned error: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 trend issues, got %+v", issues)
	}
}
