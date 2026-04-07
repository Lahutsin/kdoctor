package diagnostics

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckResourceQuotas(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	quotas, err := cs.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	for _, quota := range quotas.Items {
		for resourceName, hard := range quota.Status.Hard {
			used, ok := quota.Status.Used[resourceName]
			if !ok {
				continue
			}
			hardValue := quantityRatioBase(hard)
			usedValue := quantityRatioBase(used)
			if hardValue <= 0 {
				continue
			}
			ratio := usedValue / hardValue
			if ratio < 0.8 {
				continue
			}
			severity := SeverityWarning
			if ratio >= 1.0 {
				severity = SeverityCritical
			}
			issues = append(issues, Issue{
				Kind:           "ResourceQuota",
				Namespace:      quota.Namespace,
				Name:           quota.Name,
				Severity:       severity,
				Category:       "control-plane",
				Check:          "resource-quota",
				Summary:        fmt.Sprintf("resource quota %s at %.0f%% of hard limit", resourceName.String(), ratio*100),
				Recommendation: "Increase quota, reduce namespace usage, or rebalance workloads across namespaces.",
			})
		}
	}

	return issues, nil
}

func quantityRatioBase(quantity resource.Quantity) float64 {
	return quantity.AsApproximateFloat64()
}
