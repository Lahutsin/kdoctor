package diagnostics

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CheckControlPlane inspects etcd liveness and core control-plane pods (scheduler/controller-manager).
func CheckControlPlane(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}

	var issues []Issue

	if etcdIssue := probeEtcd(ctx, cs); etcdIssue != nil {
		issues = append(issues, *etcdIssue)
	}

	schedIssues, err := checkComponentPods(ctx, cs, "kube-scheduler")
	if err != nil {
		return nil, err
	}
	issues = append(issues, schedIssues...)

	cmIssues, err := checkComponentPods(ctx, cs, "kube-controller-manager")
	if err != nil {
		return nil, err
	}
	issues = append(issues, cmIssues...)

	securityIssues, err := CheckControlPlaneSecurity(ctx, cs)
	if err != nil {
		return nil, err
	}
	issues = append(issues, securityIssues...)

	return issues, nil
}

func probeEtcd(ctx context.Context, cs *kubernetes.Clientset) *Issue {
	start := time.Now()
	result := cs.Discovery().RESTClient().Get().AbsPath("/livez/etcd").Do(ctx)
	var code int
	result.StatusCode(&code)
	_, err := result.Raw()
	latency := time.Since(start)

	if err != nil {
		if code == 404 {
			return nil // endpoint not exposed; skip
		}
		summary := fmt.Sprintf("etcd livez failed (status %d)", code)
		return &Issue{
			Kind:           "etcd",
			Severity:       SeverityCritical,
			Category:       "control-plane",
			Check:          "etcd-livez",
			Summary:        summary,
			Recommendation: "Check etcd pods/endpoints, quorum, TLS certs, and network; inspect etcd logs and disk IO.",
		}
	}
	if latency > 700*time.Millisecond {
		summary := fmt.Sprintf("etcd livez slow (~%dms)", latency.Milliseconds())
		return &Issue{
			Kind:           "etcd",
			Severity:       SeverityWarning,
			Category:       "control-plane",
			Check:          "etcd-latency",
			Summary:        summary,
			Recommendation: "Investigate etcd disk latency, network, and control-plane load; consider defragmentation and compaction policies.",
		}
	}

	if sizeIssue := probeEtcdSize(ctx, cs); sizeIssue != nil {
		return sizeIssue
	}
	return nil
}

// probeEtcdSize inspects etcd metrics for DB size to hint defrag needs.
func probeEtcdSize(ctx context.Context, cs *kubernetes.Clientset) *Issue {
	res := cs.Discovery().RESTClient().Get().AbsPath("/metrics").Do(ctx)
	raw, err := res.Raw()
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var dbSize float64
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "etcd_mvcc_db_total_size_in_bytes") {
			if v, ok := parsePromGauge(line); ok {
				dbSize = v
				break
			}
		}
	}
	if dbSize == 0 {
		return nil
	}

	gb := dbSize / (1024 * 1024 * 1024)
	switch {
	case gb >= 2.0:
		return &Issue{
			Kind:           "etcd",
			Severity:       SeverityWarning,
			Category:       "control-plane",
			Check:          "etcd-size",
			Summary:        fmt.Sprintf("etcd DB size ~%.2fGiB", gb),
			Recommendation: "Consider etcd defragmentation and review compaction/retention; ensure disk IO is healthy.",
		}
	case gb >= 1.0:
		return &Issue{
			Kind:           "etcd",
			Severity:       SeverityInfo,
			Category:       "control-plane",
			Check:          "etcd-size",
			Summary:        fmt.Sprintf("etcd DB size ~%.2fGiB", gb),
			Recommendation: "Monitor growth; schedule defrag during maintenance if size keeps increasing.",
		}
	}
	return nil
}

func checkComponentPods(ctx context.Context, cs *kubernetes.Clientset, component string) ([]Issue, error) {
	pods, err := cs.CoreV1().Pods(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("component=%s", component),
		Limit:         10,
	})
	if err != nil {
		return nil, err
	}
	issues := make([]Issue, 0)
	if len(pods.Items) == 0 {
		issues = append(issues, Issue{
			Kind:           "ControlPlane",
			Namespace:      metav1.NamespaceSystem,
			Name:           component,
			Severity:       SeverityCritical,
			Category:       "control-plane",
			Check:          "controlplane-pods",
			Summary:        fmt.Sprintf("no pods found for %s", component),
			Recommendation: "Ensure control-plane static pods are running on master nodes; check kubelet and manifest files.",
		})
		return issues, nil
	}

	var firstPod *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !isPodReady(pod) {
			issues = append(issues, Issue{
				Kind:           "ControlPlane",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityCritical,
				Category:       "control-plane",
				Check:          "controlplane-pods",
				Summary:        fmt.Sprintf("%s pod not Ready", component),
				Recommendation: "Inspect pod logs and events for the control-plane component; check certs, flags, and host resources.",
			})
		}
		if firstPod == nil {
			firstPod = pod
		}
	}

	if firstPod != nil {
		issues = append(issues, scrapeComponentMetrics(ctx, cs, *firstPod, component)...)
	}

	return issues, nil
}

func isPodReady(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// scrapeComponentMetrics pulls minimal metrics from a control-plane pod via the API proxy.
func scrapeComponentMetrics(ctx context.Context, cs *kubernetes.Clientset, pod corev1.Pod, component string) []Issue {
	path := "/metrics"
	res := cs.CoreV1().RESTClient().Get().Namespace(pod.Namespace).Resource("pods").Name(pod.Name).SubResource("proxy").Suffix(strings.TrimPrefix(path, "/")).Do(ctx)
	raw, err := res.Raw()
	if err != nil {
		return []Issue{issueFromComponent(component, SeverityWarning, fmt.Sprintf("failed to scrape metrics for %s: %v", pod.Name, err), "Ensure metrics endpoint is exposed and reachable via API proxy.")}
	}

	var issues []Issue
	switch component {
	case "kube-scheduler":
		issues = append(issues, parseSchedulerMetrics(raw)...)
	case "kube-controller-manager":
		issues = append(issues, parseControllerManagerMetrics(raw)...)
	}
	return issues
}

func parseSchedulerMetrics(data []byte) []Issue {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var pending float64
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "scheduler_pending_pods") {
			if v, ok := parsePromGauge(line); ok {
				pending = v
			}
		}
	}
	if pending > 0 {
		return []Issue{issueFromComponent("kube-scheduler", SeverityWarning, fmt.Sprintf("scheduler has pending pods gauge=%.0f", pending), "Check scheduling logs, node availability, taints/tolerations, and resource pressure.")}
	}
	return nil
}

func parseControllerManagerMetrics(data []byte) []Issue {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var maxDepth float64
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "workqueue_depth") {
			if v, ok := parsePromGauge(line); ok && v > maxDepth {
				maxDepth = v
			}
		}
	}
	if maxDepth > 100 {
		return []Issue{issueFromComponent("kube-controller-manager", SeverityWarning, fmt.Sprintf("controller workqueue depth high (%.0f)", maxDepth), "Investigate controller-manager load, API latency, and reconcile loops; check etcd and apiserver health.")}
	}
	return nil
}

func parsePromGauge(line string) (float64, bool) {
	if i := strings.LastIndex(line, " "); i != -1 && i < len(line)-1 {
		v, err := strconv.ParseFloat(strings.TrimSpace(line[i+1:]), 64)
		if err == nil {
			return v, true
		}
	}
	return 0, false
}

func issueFromComponent(component string, sev Severity, summary, rec string) Issue {
	return Issue{
		Kind:           "ControlPlane",
		Namespace:      metav1.NamespaceSystem,
		Name:           component,
		Severity:       sev,
		Category:       "control-plane",
		Check:          "controlplane-metrics",
		Summary:        summary,
		Recommendation: rec,
	}
}
