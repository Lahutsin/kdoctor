package diagnostics

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckNodes highlights nodes that are NotReady or under pressure conditions.
func CheckNodes(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)

	for _, node := range nodes.Items {
		readyCond := nodeReadyCondition(node.Status.Conditions)
		if readyCond == nil || readyCond.Status != v1.ConditionTrue {
			summary := "node is NotReady"
			if readyCond != nil && readyCond.Reason != "" {
				summary = fmt.Sprintf("node is NotReady: %s", readyCond.Reason)
				if readyCond.Message != "" {
					summary = fmt.Sprintf("%s (%s)", summary, readyCond.Message)
				}
			}
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityCritical,
				Summary:        summary,
				Recommendation: "Check kubelet status, node reachability, and control-plane logs; run kubectl describe node for condition details.",
			})
		}

		for _, cond := range node.Status.Conditions {
			if cond.Status != v1.ConditionTrue {
				continue
			}
			switch cond.Type {
			case v1.NodeMemoryPressure:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Summary:        "node reports memory pressure",
					Recommendation: "Evict or reschedule pods, increase node memory, or tune resource requests/limits.",
				})
			case v1.NodeDiskPressure:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Summary:        "node reports disk pressure",
					Recommendation: "Free disk space, rotate logs, or expand the node volume.",
				})
			case v1.NodeNetworkUnavailable:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Summary:        "node network is unavailable",
					Recommendation: "Verify CNI plugin, node routes, and cloud provider networking.",
				})
			}
		}
	}

	return issues, nil
}

func nodeReadyCondition(conditions []v1.NodeCondition) *v1.NodeCondition {
	for i := range conditions {
		if conditions[i].Type == v1.NodeReady {
			return &conditions[i]
		}
	}
	return nil
}
