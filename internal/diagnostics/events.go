package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckWarningEvents fetches recent warning events for fast triage.
func CheckWarningEvents(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	events, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-30 * time.Minute)

	issues := make([]Issue, 0)
	for _, ev := range events.Items {
		if ev.EventTime.Time.Before(cutoff) && ev.LastTimestamp.Time.Before(cutoff) && ev.CreationTimestamp.Time.Before(cutoff) {
			continue
		}
		objKind := ev.InvolvedObject.Kind
		name := ev.InvolvedObject.Name
		nsForObj := ev.InvolvedObject.Namespace
		if nsForObj == "" {
			nsForObj = ns
		}

		recommendation := "Inspect the referenced object and resolve the cause reported in the event message."
		if strings.Contains(strings.ToLower(ev.Reason), "backoff") {
			recommendation = "Check pod logs and readiness probes; resolve the crash loop or failing init containers."
		}

		issues = append(issues, Issue{
			Kind:           objKind,
			Namespace:      nsForObj,
			Name:           name,
			Severity:       SeverityInfo,
			Summary:        fmt.Sprintf("recent warning event: %s - %s", ev.Reason, ev.Message),
			Recommendation: recommendation,
		})
	}

	return issues, nil
}
