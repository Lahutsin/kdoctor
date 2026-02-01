package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// CheckControllers inspects core controllers: Deployments, DaemonSets, ReplicaSets, Jobs, CronJobs.
func CheckControllers(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var issues []Issue

	deploys, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, d := range deploys.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if d.Status.AvailableReplicas < desired {
			summary := fmt.Sprintf("deployment not fully available (%d/%d)", d.Status.AvailableReplicas, desired)
			if detail := samplePodIssue(ctx, cs, d.Namespace, d.Spec.Selector.MatchLabels); detail != "" {
				summary = fmt.Sprintf("%s; %s", summary, detail)
			}
			issues = append(issues, Issue{
				Kind:           "Deployment",
				Namespace:      d.Namespace,
				Name:           d.Name,
				Severity:       SeverityWarning,
				Summary:        summary,
				Recommendation: "Check rollout status: kubectl rollout status deploy/NAME; describe pods for failures; verify image/tag and readiness probes.",
			})
		}
	}

	daemonsets, err := cs.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ds := range daemonsets.Items {
		desired := ds.Status.DesiredNumberScheduled
		available := ds.Status.NumberAvailable
		if desired > available {
			summary := fmt.Sprintf("daemonset not fully available (%d/%d)", available, desired)
			if detail := samplePodIssue(ctx, cs, ds.Namespace, ds.Spec.Selector.MatchLabels); detail != "" {
				summary = fmt.Sprintf("%s; %s", summary, detail)
			}
			issues = append(issues, Issue{
				Kind:           "DaemonSet",
				Namespace:      ds.Namespace,
				Name:           ds.Name,
				Severity:       SeverityWarning,
				Summary:        summary,
				Recommendation: "Check daemonset pods: kubectl describe ds/NAME and affected pods; verify node selectors/taints and image pulls.",
			})
		}
	}

	replicasets, err := cs.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, rs := range replicasets.Items {
		desired := int32(1)
		if rs.Spec.Replicas != nil {
			desired = *rs.Spec.Replicas
		}
		if rs.Status.ReadyReplicas < desired {
			summary := fmt.Sprintf("replicaset not ready (%d/%d)", rs.Status.ReadyReplicas, desired)
			if detail := samplePodIssue(ctx, cs, rs.Namespace, rs.Spec.Selector.MatchLabels); detail != "" {
				summary = fmt.Sprintf("%s; %s", summary, detail)
			}
			issues = append(issues, Issue{
				Kind:           "ReplicaSet",
				Namespace:      rs.Namespace,
				Name:           rs.Name,
				Severity:       SeverityInfo,
				Summary:        summary,
				Recommendation: "Check owner deployment rollout and pod events; ensure pods schedule and containers start.",
			})
		}
	}

	jobs, err := cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, job := range jobs.Items {
		if failedCondition(job.Status.Conditions) {
			issues = append(issues, Issue{
				Kind:           "Job",
				Namespace:      job.Namespace,
				Name:           job.Name,
				Severity:       SeverityCritical,
				Summary:        "job failed",
				Recommendation: "Inspect job pods: kubectl logs job/NAME; check backoffLimit, image, and command/args.",
			})
			continue
		}
		if job.Status.Failed > 0 && job.Status.Succeeded == 0 && job.Status.Active == 0 {
			issues = append(issues, Issue{
				Kind:           "Job",
				Namespace:      job.Namespace,
				Name:           job.Name,
				Severity:       SeverityWarning,
				Summary:        fmt.Sprintf("job failures recorded (%d failed pods)", job.Status.Failed),
				Recommendation: "Inspect failed pods: kubectl logs -p; verify resources and environment variables.",
			})
		}
	}

	cronjobs, err := cs.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
	} else {
		issues = append(issues, evaluateCronJobsV1(cronjobs.Items)...)
	}

	return issues, nil
}

func failedCondition(conds []batchv1.JobCondition) bool {
	for _, c := range conds {
		if c.Type == batchv1.JobFailed && c.Status == "True" {
			return true
		}
	}
	return false
}

func evaluateCronJobsV1(items []batchv1.CronJob) []Issue {
	issues := make([]Issue, 0)
	now := time.Now()
	for _, cj := range items {
		if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
			issues = append(issues, Issue{
				Kind:           "CronJob",
				Namespace:      cj.Namespace,
				Name:           cj.Name,
				Severity:       SeverityInfo,
				Summary:        "cronjob is suspended",
				Recommendation: "Unsuspend to resume schedules: kubectl patch cronjob NAME -p '{\"spec\": {\"suspend\": false}}'",
			})
			continue
		}
		if cj.Status.LastScheduleTime != nil && cj.Status.LastSuccessfulTime == nil {
			if now.Sub(cj.Status.LastScheduleTime.Time) > time.Hour {
				issues = append(issues, Issue{
					Kind:           "CronJob",
					Namespace:      cj.Namespace,
					Name:           cj.Name,
					Severity:       SeverityWarning,
					Summary:        "no successful cronjob runs observed",
					Recommendation: "Inspect recent job pods for failures and check cron schedule syntax.",
				})
			}
		}
	}
	return issues
}

// samplePodIssue returns a brief failing pod reason for the given selector, if any.
func samplePodIssue(ctx context.Context, cs *kubernetes.Clientset, namespace string, selector map[string]string) string {
	if len(selector) == 0 {
		return ""
	}
	ls := labels.SelectorFromSet(selector).String()
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: ls, Limit: 10})
	if err != nil {
		return ""
	}
	for _, pod := range pods.Items {
		if detail := summarizePodState(ctx, cs, &pod); detail != "" {
			return fmt.Sprintf("pod %s: %s", pod.Name, detail)
		}
	}
	return ""
}

// summarizePodState extracts a short failure reason for a pod plus optional evidence.
func summarizePodState(ctx context.Context, cs *kubernetes.Clientset, pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse && cond.Reason != "" {
			return fmt.Sprintf("unschedulable: %s", cond.Reason)
		}
	}

	for _, cStatus := range pod.Status.ContainerStatuses {
		if cStatus.State.Waiting != nil {
			reason := cStatus.State.Waiting.Reason
			msg := cStatus.State.Waiting.Message
			if msg != "" {
				return fmt.Sprintf("container %s waiting: %s (%s); %s", cStatus.Name, reason, msg, fetchPodEvidence(ctx, cs, pod, cStatus.Name))
			}
			return fmt.Sprintf("container %s waiting: %s; %s", cStatus.Name, reason, fetchPodEvidence(ctx, cs, pod, cStatus.Name))
		}
		if cStatus.LastTerminationState.Terminated != nil {
			term := cStatus.LastTerminationState.Terminated
			reason := term.Reason
			if reason == "" {
				reason = term.Message
			}
			return fmt.Sprintf("container %s terminated: %s (exit %d); %s", cStatus.Name, reason, term.ExitCode, fetchPodEvidence(ctx, cs, pod, cStatus.Name))
		}
		if cStatus.State.Terminated != nil {
			term := cStatus.State.Terminated
			reason := term.Reason
			if reason == "" {
				reason = term.Message
			}
			return fmt.Sprintf("container %s terminated now: %s (exit %d); %s", cStatus.Name, reason, term.ExitCode, fetchPodEvidence(ctx, cs, pod, cStatus.Name))
		}
		if cStatus.Ready == false && cStatus.RestartCount > 0 {
			return fmt.Sprintf("container %s not ready; restarts=%d; %s", cStatus.Name, cStatus.RestartCount, fetchPodEvidence(ctx, cs, pod, cStatus.Name))
		}
	}
	return ""
}

// fetchPodEvidence pulls a small event and log tail snippet to enrich rollout diagnostics.
func fetchPodEvidence(ctx context.Context, client *kubernetes.Clientset, pod *corev1.Pod, container string) string {
	if client == nil || pod == nil {
		return ""
	}
	pieces := make([]string, 0, 2)

	evs, err := client.CoreV1().Events(pod.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.uid=%s,type=Warning", pod.Name, pod.UID),
		Limit:         3,
	})
	if err == nil && len(evs.Items) > 0 {
		msgs := make([]string, 0, len(evs.Items))
		for _, ev := range evs.Items {
			msgs = append(msgs, fmt.Sprintf("%s: %s", ev.Reason, ev.Message))
		}
		pieces = append(pieces, fmt.Sprintf("events: %s", strings.Join(msgs, "; ")))
	}

	opts := &corev1.PodLogOptions{TailLines: int64Ptr(5)}
	if container != "" {
		opts.Container = container
	}
	logReq := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, opts)
	if raw, err := logReq.Do(ctx).Raw(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) > 3 {
			lines = lines[len(lines)-3:]
		}
		if len(lines) > 0 && lines[0] != "" {
			pieces = append(pieces, fmt.Sprintf("logs tail: %s", strings.Join(lines, " | ")))
		}
	}

	return strings.Join(pieces, "; ")
}

func int64Ptr(v int64) *int64 {
	return &v
}
