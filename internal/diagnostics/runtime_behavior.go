package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckRuntimeBehavior(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	pods, err := listPodsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	events, err := listEventsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	cronjobs, err := listCronJobsCached(ctx, cs, ns)
	if err != nil {
		cronjobs = nil
	}
	daemonsets, err := listDaemonSetsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	nodes, err := listNodesCached(ctx, cs)
	if err != nil {
		return nil, err
	}
	serviceAccounts, err := listServiceAccountsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}

	saIndex := make(map[string]corev1.ServiceAccount, len(serviceAccounts))
	for _, sa := range serviceAccounts {
		saIndex[serviceAccountKey(sa.Namespace, sa.Name)] = sa
	}

	issues := make([]Issue, 0)
	issues = append(issues, suspiciousRestartPatternIssues(pods)...)
	issues = append(issues, unexpectedExecUsageIssues(events)...)
	issues = append(issues, recentEphemeralDebugContainerIssues(pods, events)...)
	issues = append(issues, recentPrivilegedPodIssues(pods, namespaces)...)
	issues = append(issues, suspiciousOutboundBehaviorIssues(pods)...)
	issues = append(issues, unusualListeningPortIssues(pods)...)
	issues = append(issues, namespacePodChurnIssues(pods, events, namespaces)...)
	issues = append(issues, recentUnexpectedTokenMountIssues(pods, saIndex, namespaces)...)
	issues = append(issues, unusualCronJobIssues(cronjobs, namespaces)...)
	issues = append(issues, unexpectedDaemonSetIssues(daemonsets, pods, nodes, namespaces)...)

	return dedupeIssues(issues), nil
}

func suspiciousRestartPatternIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	now := time.Now()
	for _, pod := range pods {
		podAge := now.Sub(pod.CreationTimestamp.Time)
		for _, status := range append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...) {
			pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, status)
		}
		totalRestarts := int32(0)
		for _, status := range pod.Status.ContainerStatuses {
			totalRestarts += status.RestartCount
			if status.RestartCount >= 10 || (status.RestartCount >= 3 && podAge <= time.Hour) {
				severity := SeverityWarning
				if status.RestartCount >= 20 || podAge <= 30*time.Minute {
					severity = SeverityCritical
				}
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       severity,
					Category:       "workloads",
					Check:          "runtime-restart-pattern",
					Summary:        fmt.Sprintf("container %s shows suspicious restart behavior (%d restarts, pod age %s)", status.Name, status.RestartCount, humanDuration(podAge)),
					Recommendation: "Investigate whether this is crash-loop abuse, repeated exec/debugging, or unstable rollout behavior rather than normal application restarts.",
				})
			}
		}
		if totalRestarts >= 25 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "runtime-restart-pattern",
				Summary:        fmt.Sprintf("pod accumulated a high overall restart count (%d)", totalRestarts),
				Recommendation: "Review restart history, rollout timing, and whether this pod is being repeatedly probed, debugged, or recycled unexpectedly.",
			})
		}
	}
	return issues
}

func unexpectedExecUsageIssues(events []corev1.Event) []Issue {
	issues := make([]Issue, 0)
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, event := range events {
		when := eventTimestamp(event)
		if when.Before(cutoff) {
			continue
		}
		text := strings.ToLower(event.Reason + " " + event.Message)
		if !containsAny(text, []string{"exec", "attach", "portforward", "remotecommand"}) {
			continue
		}
		kind := event.InvolvedObject.Kind
		if kind == "" {
			kind = "Pod"
		}
		issues = append(issues, Issue{
			Kind:           kind,
			Namespace:      event.Namespace,
			Name:           event.InvolvedObject.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "runtime-exec-usage",
			Summary:        fmt.Sprintf("recent exec/attach-style activity observed: %s", strings.TrimSpace(event.Reason+" "+truncateString(event.Message, 120))),
			Recommendation: "Review audit logs or operator access patterns to confirm interactive access into pods was expected and authorized.",
		})
	}
	return issues
}

func recentEphemeralDebugContainerIssues(pods []corev1.Pod, events []corev1.Event) []Issue {
	issues := make([]Issue, 0)
	cutoff := time.Now().Add(-24 * time.Hour)
	eventPods := map[string]struct{}{}
	for _, event := range events {
		if eventTimestamp(event).Before(cutoff) {
			continue
		}
		text := strings.ToLower(event.Reason + " " + event.Message)
		if containsAny(text, []string{"ephemeral", "debug container", "kubectl debug"}) {
			eventPods[event.Namespace+"/"+event.InvolvedObject.Name] = struct{}{}
		}
	}
	for _, pod := range pods {
		if len(pod.Spec.EphemeralContainers) == 0 {
			continue
		}
		severity := SeverityWarning
		if _, ok := eventPods[pod.Namespace+"/"+pod.Name]; ok || pod.CreationTimestamp.Time.After(cutoff) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "runtime-ephemeral-debug",
			Summary:        fmt.Sprintf("pod has ephemeral debug containers attached (%d)", len(pod.Spec.EphemeralContainers)),
			Recommendation: "Confirm recent debugging was expected, then remove lingering ephemeral containers and review operator access if this pod is production or sensitive.",
		})
	}
	return issues
}

func recentPrivilegedPodIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, pod := range pods {
		if pod.CreationTimestamp.Time.Before(cutoff) {
			continue
		}
		privileged := false
		for _, container := range allSecurityContainers(pod) {
			if isPrivileged(container.securityContext) {
				privileged = true
				break
			}
		}
		if !privileged {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[pod.Namespace]) || isSensitiveWorkload(pod, namespaces[pod.Namespace]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "runtime-new-privileged-pod",
			Summary:        fmt.Sprintf("privileged pod was launched recently (age %s)", humanDuration(time.Since(pod.CreationTimestamp.Time))),
			Recommendation: "Review the rollout, owner controller, and operator actions to confirm this privileged pod launch was intentional.",
		})
	}
	return issues
}

func suspiciousOutboundBehaviorIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		findings := make([]string, 0)
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			fields := []string{container.Name, container.Image}
			fields = append(fields, container.Command...)
			fields = append(fields, container.Args...)
			for _, env := range container.Env {
				fields = append(fields, env.Name+"="+env.Value)
			}
			for _, field := range fields {
				text := strings.ToLower(field)
				if containsAny(text, miningMarkers()) {
					findings = append(findings, truncateString(field, 80))
				}
			}
		}
		if len(findings) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "runtime-suspicious-egress",
			Summary:        fmt.Sprintf("workload contains crypto-mining or suspicious outbound connection markers: %s", strings.Join(uniqueStrings(findings), ", ")),
			Recommendation: "Investigate the image, command line, and egress destinations immediately; this looks closer to compromise or unauthorized software than normal application behavior.",
		})
	}
	return issues
}

func unusualListeningPortIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		findings := make([]string, 0)
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			for _, port := range container.Ports {
				if !looksUnusualContainerPort(port) {
					continue
				}
				findings = append(findings, fmt.Sprintf("%s:%d", container.Name, port.ContainerPort))
			}
		}
		if len(findings) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityInfo,
			Category:       "workloads",
			Check:          "runtime-unusual-ports",
			Summary:        fmt.Sprintf("container declares unusual listening ports: %s", strings.Join(uniqueStrings(findings), ", ")),
			Recommendation: "Verify that these ports are expected for the workload; unusual listener ports can indicate embedded admin services, tunnels, or unauthorized software.",
		})
	}
	return issues
}

func namespacePodChurnIssues(pods []corev1.Pod, events []corev1.Event, namespaces map[string]namespaceMeta) []Issue {
	type churnBucket struct {
		created int
		events  int
		pods    map[string]struct{}
	}
	cutoff := time.Now().Add(-30 * time.Minute)
	buckets := map[string]*churnBucket{}
	for _, pod := range pods {
		if pod.CreationTimestamp.Time.Before(cutoff) {
			continue
		}
		bucket := buckets[pod.Namespace]
		if bucket == nil {
			bucket = &churnBucket{pods: map[string]struct{}{}}
			buckets[pod.Namespace] = bucket
		}
		bucket.created++
		bucket.pods[pod.Name] = struct{}{}
	}
	for _, event := range events {
		if eventTimestamp(event).Before(cutoff) || event.InvolvedObject.Kind != "Pod" {
			continue
		}
		text := strings.ToLower(event.Reason + " " + event.Message)
		if !containsAny(text, []string{"scheduled", "pulling", "created", "started", "killing", "evict", "back-off", "backoff", "deleted"}) {
			continue
		}
		bucket := buckets[event.Namespace]
		if bucket == nil {
			bucket = &churnBucket{pods: map[string]struct{}{}}
			buckets[event.Namespace] = bucket
		}
		bucket.events += maxInt(int(event.Count), 1)
		if event.InvolvedObject.Name != "" {
			bucket.pods[event.InvolvedObject.Name] = struct{}{}
		}
	}
	issues := make([]Issue, 0)
	for namespace, bucket := range buckets {
		if bucket.created < 8 && bucket.events < 20 {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[namespace]) || bucket.created >= 15 || bucket.events >= 40 {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Namespace",
			Name:           namespace,
			Severity:       severity,
			Category:       "workloads",
			Check:          "runtime-pod-churn",
			Summary:        fmt.Sprintf("namespace shows sudden pod churn in the last 30m (%d new pods, %d pod lifecycle events across %d pods)", bucket.created, bucket.events, len(bucket.pods)),
			Recommendation: "Review recent rollouts, autoscaling, crash loops, and batch jobs; sudden churn can also indicate disruptive debugging, eviction storms, or malicious activity.",
		})
	}
	return issues
}

func recentUnexpectedTokenMountIssues(pods []corev1.Pod, serviceAccounts map[string]corev1.ServiceAccount, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, pod := range pods {
		if pod.CreationTimestamp.Time.Before(cutoff) {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		sa := serviceAccounts[serviceAccountKey(pod.Namespace, saName)]
		if !podUsesServiceAccountToken(pod, sa) || podHasProjectedToken(pod) || podLooksLikeKubernetesClient(pod) {
			continue
		}
		severity := SeverityInfo
		if isProductionNamespace(namespaces[pod.Namespace]) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "runtime-unexpected-serviceaccount-token",
			Summary:        fmt.Sprintf("recent workload mounts a service account token unexpectedly (serviceAccount=%s)", saName),
			Recommendation: "Confirm the rollout really needs Kubernetes API credentials; otherwise disable automountServiceAccountToken for this workload.",
		})
	}
	return issues
}

func unusualCronJobIssues(cronjobs []batchv1.CronJob, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, cronjob := range cronjobs {
		findings := make([]string, 0)
		if cronScheduleLooksSuspicious(cronjob.Spec.Schedule) {
			findings = append(findings, "high-frequency schedule="+cronjob.Spec.Schedule)
		}
		for _, container := range cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers {
			for _, field := range cronBehaviorFields(container) {
				text := strings.ToLower(field)
				if containsAny(text, miningMarkers()) || containsAny(text, []string{"curl ", "wget ", "nc ", "ncat ", "bash -c", "sh -c", "python -c", "socat", "openssl s_client"}) {
					findings = append(findings, truncateString(field, 80))
				}
			}
		}
		if len(findings) == 0 && !cronjob.CreationTimestamp.Time.After(time.Now().Add(-24*time.Hour)) {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[cronjob.Namespace]) || containsAny(strings.ToLower(strings.Join(findings, " ")), miningMarkers()) {
			severity = SeverityCritical
		}
		summary := "cronjob shows unusual behavioral characteristics"
		if len(findings) > 0 {
			summary = fmt.Sprintf("cronjob shows unusual behavioral characteristics: %s", strings.Join(uniqueStrings(findings), ", "))
		}
		issues = append(issues, Issue{
			Kind:           "CronJob",
			Namespace:      cronjob.Namespace,
			Name:           cronjob.Name,
			Severity:       severity,
			Category:       "workloads",
			Check:          "runtime-unusual-cronjob",
			Summary:        summary,
			Recommendation: "Review whether this scheduled job, image, and command pattern are expected; very frequent or shell-heavy cronjobs deserve explicit approval.",
		})
	}
	return issues
}

func unexpectedDaemonSetIssues(daemonsets []appsv1.DaemonSet, pods []corev1.Pod, nodes []corev1.Node, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	nodeCount := 0
	for _, node := range nodes {
		if !node.Spec.Unschedulable {
			nodeCount++
		}
	}
	if nodeCount == 0 {
		nodeCount = len(nodes)
	}
	podsByController := daemonSetPodCount(pods)
	for _, ds := range daemonsets {
		if !daemonSetLooksUnexpected(ds, nodeCount) {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[ds.Namespace]) || daemonSetTemplateLooksPrivileged(ds.Spec.Template.Spec) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "DaemonSet",
			Namespace:      ds.Namespace,
			Name:           ds.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "runtime-unexpected-daemonset",
			Summary:        fmt.Sprintf("daemonset runs broadly across the cluster and looks unexpected (%d desired, %d observed pods)", ds.Status.DesiredNumberScheduled, podsByController[ds.Namespace+"/"+ds.Name]),
			Recommendation: "Review whether this DaemonSet is an approved cluster-wide agent; new broad privileged agents should be treated as sensitive changes.",
		})
	}
	return issues
}

func daemonSetPodCount(pods []corev1.Pod) map[string]int {
	result := make(map[string]int)
	for _, pod := range pods {
		for _, owner := range pod.OwnerReferences {
			if owner.Kind == "DaemonSet" {
				result[pod.Namespace+"/"+owner.Name]++
			}
		}
	}
	return result
}

func daemonSetLooksUnexpected(ds appsv1.DaemonSet, nodeCount int) bool {
	if nodeCount <= 0 || int(ds.Status.DesiredNumberScheduled) < maxInt(nodeCount-1, 1) {
		return false
	}
	text := strings.ToLower(ds.Namespace + "/" + ds.Name)
	if containsAny(text, approvedDaemonSetMarkers()) {
		return false
	}
	if daemonSetTemplateLooksPrivileged(ds.Spec.Template.Spec) {
		return true
	}
	return ds.CreationTimestamp.Time.After(time.Now().Add(-7*24*time.Hour)) || !isSystemNamespace(ds.Namespace)
}

func daemonSetTemplateLooksPrivileged(spec corev1.PodSpec) bool {
	if spec.HostNetwork || spec.HostPID || spec.HostIPC {
		return true
	}
	for _, volume := range spec.Volumes {
		if volume.HostPath != nil {
			return true
		}
	}
	for _, container := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
		if isPrivileged(container.SecurityContext) {
			return true
		}
	}
	return false
}

func looksUnusualContainerPort(port corev1.ContainerPort) bool {
	common := map[int32]struct{}{80: {}, 443: {}, 8080: {}, 8443: {}, 9090: {}, 9091: {}, 3000: {}, 5000: {}, 5432: {}, 6379: {}, 3306: {}, 27017: {}, 5672: {}, 8081: {}, 6060: {}}
	if _, ok := common[port.ContainerPort]; ok {
		return false
	}
	if port.ContainerPort >= 30000 {
		return true
	}
	for _, suspicious := range []int32{3333, 4444, 5555, 6666, 7777, 14444, 31337} {
		if port.ContainerPort == suspicious {
			return true
		}
	}
	name := strings.ToLower(port.Name)
	return containsAny(name, []string{"debug", "shell", "proxy", "miner", "stratum", "admin"})
}

func cronScheduleLooksSuspicious(schedule string) bool {
	text := strings.TrimSpace(schedule)
	for _, marker := range []string{"* * * * *", "*/1 * * * *", "*/2 * * * *", "*/3 * * * *", "*/5 * * * *"} {
		if text == marker {
			return true
		}
	}
	return false
}

func cronBehaviorFields(container corev1.Container) []string {
	fields := []string{container.Name, container.Image}
	fields = append(fields, container.Command...)
	fields = append(fields, container.Args...)
	for _, env := range container.Env {
		fields = append(fields, env.Name+"="+env.Value)
	}
	return fields
}

func eventTimestamp(event corev1.Event) time.Time {
	when := event.LastTimestamp.Time
	if when.IsZero() {
		when = event.EventTime.Time
	}
	if when.IsZero() {
		when = event.CreationTimestamp.Time
	}
	return when
}

func approvedDaemonSetMarkers() []string {
	return []string{"kube-proxy", "calico", "cilium", "flannel", "weave", "antrea", "canal", "aws-node", "node-local-dns", "node-exporter", "datadog", "falco", "newrelic", "splunk", "fluent-bit", "fluentd", "promtail", "vector", "otel", "istio-cni", "kube-system", "monitoring", "logging", "observability"}
}

func miningMarkers() []string {
	return []string{"xmrig", "minergate", "coinhive", "cryptonight", "monero", "stratum+tcp", "stratum://", "ethash", "nanopool", "nicehash", "minexmr", "2miners", "wallet=", "rig-id", "cpu-max-threads-hint"}
}

func containsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func truncateString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}

func maxInt(values ...int) int {
	best := 0
	for _, value := range values {
		if value > best {
			best = value
		}
	}
	return best
}
