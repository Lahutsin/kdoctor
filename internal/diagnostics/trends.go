package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckClusterTrends(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	events, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-30 * time.Minute)
	preempted := 0
	evicted := 0
	for _, ev := range events.Items {
		when := ev.LastTimestamp.Time
		if when.IsZero() {
			when = ev.CreationTimestamp.Time
		}
		if when.Before(cutoff) {
			continue
		}
		reason := strings.ToLower(ev.Reason)
		message := strings.ToLower(ev.Message)
		if strings.Contains(reason, "preempt") || strings.Contains(message, "preempt") {
			preempted += int(ev.Count)
		}
		if strings.Contains(reason, "evict") || strings.Contains(message, "evicted") {
			evicted += int(ev.Count)
		}
	}

	issues := make([]Issue, 0, 2)
	if evicted >= 3 {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Severity:       SeverityWarning,
			Category:       "workloads",
			Check:          "eviction-trend",
			Summary:        fmt.Sprintf("%d eviction events observed in the last 30m", evicted),
			Recommendation: "Review node pressure, memory limits, and pod priorities to reduce evictions.",
		})
	}
	if preempted >= 3 {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Severity:       SeverityWarning,
			Category:       "workloads",
			Check:          "preemption-trend",
			Summary:        fmt.Sprintf("%d preemption events observed in the last 30m", preempted),
			Recommendation: "Check cluster capacity, priority classes, and bursty workloads competing for the same nodes.",
		})
	}

	return issues, nil
}
