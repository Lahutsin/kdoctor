package diagnostics

import (
	"context"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckPods inspects pod status and container states to detect common failures.
func CheckPods(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)

	for _, pod := range pods.Items {
		// Pending with scheduling problems.
		if pod.Status.Phase == v1.PodPending {
			if sched := findCondition(pod.Status.Conditions, v1.PodScheduled); sched != nil && sched.Status == v1.ConditionFalse {
				summary := fmt.Sprintf("pod is pending: %s", sched.Reason)
				advice := "Check node selectors, tolerations, resource requests, and available nodes. Run `kubectl describe pod` for scheduling events."
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Summary:        summary,
					Recommendation: advice,
				})
			}
		}

		// Container-level states.
		for _, cs := range pod.Status.ContainerStatuses {
			waiting := cs.State.Waiting
			terminated := cs.LastTerminationState.Terminated

			switch {
			case waiting != nil && isImagePull(waiting.Reason):
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityCritical,
					Summary:        fmt.Sprintf("image pull failure for container %s: %s", cs.Name, waiting.Reason),
					Recommendation: "Verify image name/tag, registry credentials (imagePullSecrets), and network reachability to the registry.",
					References:     []string{"https://kubernetes.io/docs/concepts/containers/images/#using-a-private-registry"},
				})
			case waiting != nil && waiting.Reason == "CrashLoopBackOff":
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityCritical,
					Summary:        fmt.Sprintf("container %s is crash looping", cs.Name),
					Recommendation: "Inspect recent logs: kubectl logs -p <pod> -c <container>. Check configuration, env vars, and readiness probes.",
				})
			case terminated != nil && terminated.Reason == "OOMKilled":
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Summary:        fmt.Sprintf("container %s was OOMKilled", cs.Name),
					Recommendation: "Increase memory requests/limits, optimize memory usage, or reduce workload concurrency.",
					References:     []string{"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"},
				})
			case waiting != nil && waiting.Reason == "CreateContainerConfigError":
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Summary:        fmt.Sprintf("container %s failed to start due to config error", cs.Name),
					Recommendation: "Check volumes, secrets, and configmaps referenced by the pod; validate securityContext and field references.",
				})
			}

			if cs.RestartCount > 5 {
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityInfo,
					Summary:        fmt.Sprintf("container %s restarted %d times", cs.Name, cs.RestartCount),
					Recommendation: "Investigate container logs and readiness probes; consider increasing liveness thresholds.",
				})
			}
		}
	}

	return issues, nil
}

func isImagePull(reason string) bool {
	if reason == "" {
		return false
	}
	reason = strings.ToLower(reason)
	return strings.Contains(reason, "imagepull") || strings.Contains(reason, "errimage")
}

func findCondition(conditions []v1.PodCondition, condType v1.PodConditionType) *v1.PodCondition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
