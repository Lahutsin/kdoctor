package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckWarningEvents(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: []corev1.Event{
			{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(time.Now())}, Reason: "BackOff", Message: "container restarted", InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "api"}},
			{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))}, Reason: "Old", Message: "ignore me", InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "old"}},
		}})
	})
	issues, err := CheckWarningEvents(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckWarningEvents returned error: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Recommendation, "crash loop") {
		t.Fatalf("unexpected warning events issues: %+v", issues)
	}
}
