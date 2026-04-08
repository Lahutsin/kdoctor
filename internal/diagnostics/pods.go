package diagnostics

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

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
	registryHosts := map[string]struct{}{}

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
					Category:       "workloads",
					Check:          "pod-scheduling",
					Summary:        summary,
					Recommendation: advice,
				})
			}
		}

		// Container-level states.
		for _, containerSpec := range pod.Spec.Containers {
			if registryHost := imageRegistryHost(containerSpec.Image); registryHost != "" {
				registryHosts[registryHost] = struct{}{}
			}
			if containerSpec.ImagePullPolicy == v1.PullAlways && strings.HasSuffix(containerSpec.Image, ":latest") {
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityInfo,
					Category:       "workloads",
					Check:          "image-policy",
					Summary:        fmt.Sprintf("container %s uses imagePullPolicy=Always with :latest", containerSpec.Name),
					Recommendation: "Pin image tags to immutable versions to reduce rollout drift and unnecessary registry pulls.",
				})
			}
		}

		for _, secretRef := range pod.Spec.ImagePullSecrets {
			if _, err := cs.CoreV1().Secrets(pod.Namespace).Get(ctx, secretRef.Name, metav1.GetOptions{}); err != nil {
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Category:       "workloads",
					Check:          "image-pull-secret",
					Summary:        fmt.Sprintf("imagePullSecret %s is missing or unreadable", secretRef.Name),
					Recommendation: "Restore the referenced secret or update the pod spec/service account to a valid imagePullSecret.",
				})
			}
		}

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
					Category:       "workloads",
					Check:          "image-pull",
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
					Category:       "workloads",
					Check:          "crashloop",
					Summary:        fmt.Sprintf("container %s is crash looping", cs.Name),
					Recommendation: "Inspect recent logs: kubectl logs -p <pod> -c <container>. Check configuration, env vars, and readiness probes.",
				})
			case terminated != nil && terminated.Reason == "OOMKilled":
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Category:       "workloads",
					Check:          "oomkilled",
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
					Category:       "workloads",
					Check:          "config-error",
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
					Category:       "workloads",
					Check:          "restarts",
					Summary:        fmt.Sprintf("container %s restarted %d times", cs.Name, cs.RestartCount),
					Recommendation: "Investigate container logs and readiness probes; consider increasing liveness thresholds.",
				})
			}
		}
	}

	if !HostNetworkProbeEnabled("registry") {
		return issues, nil
	}

	for registryHost := range registryHosts {
		conn, err := net.DialTimeout("tcp", registryHost, 2*time.Second)
		if err != nil {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Name:           registryHost,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "registry-reachability",
				Detection:      "active-probe",
				Confidence:     "medium",
				Summary:        fmt.Sprintf("registry endpoint %s is not reachable from the diagnostic host", registryHost),
				Recommendation: "Verify outbound network access, registry DNS, VPN/proxy settings, and whether the cluster uses a private registry endpoint.",
			})
			continue
		}
		_ = conn.Close()
	}

	return issues, nil
}

func imageRegistryHost(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	parts := strings.Split(image, "/")
	if len(parts) == 0 {
		return ""
	}
	host := parts[0]
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") && host != "localhost" {
		return "registry-1.docker.io:443"
	}
	if !strings.Contains(host, ":") {
		return host + ":443"
	}
	return host
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
