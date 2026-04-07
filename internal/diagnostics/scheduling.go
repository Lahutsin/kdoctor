package diagnostics

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckScheduling(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var issues []Issue
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" || pod.Status.Phase != corev1.PodPending {
			continue
		}
		if untolerated := untoleratedNodeTaints(pod.Spec.Tolerations, nodes.Items); len(untolerated) > 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "taints-tolerations",
				Summary:        fmt.Sprintf("pending pod may not tolerate node taints: %s", untolerated[0]),
				Recommendation: "Review pod tolerations and node taints, especially after node pools or control-plane labels changed.",
			})
		}
	}

	return issues, nil
}

func untoleratedNodeTaints(tolerations []corev1.Toleration, nodes []corev1.Node) []string {
	issues := make([]string, 0)
	for _, node := range nodes {
		for _, taint := range node.Spec.Taints {
			if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
				continue
			}
			if toleratesTaint(tolerations, taint) {
				continue
			}
			issues = append(issues, fmt.Sprintf("%s=%s:%s on node %s", taint.Key, taint.Value, taint.Effect, node.Name))
		}
	}
	return issues
}

func toleratesTaint(tolerations []corev1.Toleration, taint corev1.Taint) bool {
	for _, tol := range tolerations {
		if tol.Key != taint.Key {
			continue
		}
		if tol.Effect != "" && tol.Effect != taint.Effect {
			continue
		}
		if tol.Operator == corev1.TolerationOpExists {
			return true
		}
		if tol.Value == taint.Value {
			return true
		}
	}
	return false
}
