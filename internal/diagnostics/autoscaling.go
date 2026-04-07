package diagnostics

import (
	"context"
	"fmt"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckAutoscaling(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	hpas, err := cs.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	for _, hpa := range hpas.Items {
		issues = append(issues, evaluateHPAConditions(hpa.Status.Conditions, hpa.Namespace, hpa.Name)...)
		if len(hpa.Status.CurrentMetrics) == 0 {
			issues = append(issues, Issue{
				Kind:           "HPA",
				Namespace:      hpa.Namespace,
				Name:           hpa.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "hpa-metrics",
				Summary:        "HPA has no current metrics",
				Recommendation: "Check metrics-server or custom metrics adapters and verify the scale target exposes the expected metrics.",
			})
		}
		if hpa.Spec.MinReplicas != nil && hpa.Status.CurrentReplicas == *hpa.Spec.MinReplicas && hpa.Status.DesiredReplicas > hpa.Status.CurrentReplicas {
			issues = append(issues, Issue{
				Kind:           "HPA",
				Namespace:      hpa.Namespace,
				Name:           hpa.Name,
				Severity:       SeverityInfo,
				Category:       "workloads",
				Check:          "hpa-scale-lag",
				Summary:        fmt.Sprintf("HPA wants %d replicas but currently has %d", hpa.Status.DesiredReplicas, hpa.Status.CurrentReplicas),
				Recommendation: "Check pending pods, quota limits, and metrics freshness if scaling appears stalled.",
			})
		}
	}

	return issues, nil
}

func evaluateHPAConditions(conditions []autoscalingv2.HorizontalPodAutoscalerCondition, namespace, name string) []Issue {
	issues := make([]Issue, 0)
	for _, cond := range conditions {
		if cond.Status == corev1.ConditionTrue {
			if cond.Type == autoscalingv2.ScalingLimited {
				issues = append(issues, Issue{
					Kind:           "HPA",
					Namespace:      namespace,
					Name:           name,
					Severity:       SeverityInfo,
					Category:       "workloads",
					Check:          "hpa-scaling-limited",
					Summary:        fmt.Sprintf("HPA scaling is limited: %s", cond.Message),
					Recommendation: "Review maxReplicas/minReplicas and upstream resource constraints.",
				})
			}
			continue
		}
		if cond.Type == autoscalingv2.ScalingActive || cond.Type == autoscalingv2.AbleToScale {
			issues = append(issues, Issue{
				Kind:           "HPA",
				Namespace:      namespace,
				Name:           name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "hpa-condition",
				Summary:        fmt.Sprintf("HPA condition %s is %s: %s", cond.Type, cond.Status, cond.Message),
				Recommendation: "Inspect metrics APIs, scale target health, and autoscaler controller logs.",
			})
		}
	}
	return issues
}
