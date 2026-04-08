package diagnostics

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var prometheusRuleGVR = schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheusrules"}

func CheckObservabilityAndDetection(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}
	if ns != metav1.NamespaceAll {
		return nil, NotApplicableError("observability check currently requires all-namespaces scope")
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	deployments, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	daemonsets, err := cs.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	configMaps, err := cs.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		configMaps = &corev1.ConfigMapList{}
	}
	ruleCorpus := collectAlertRuleCorpus(ctx, dyn, ns, configMaps.Items)
	issues := make([]Issue, 0)
	issues = append(issues, auditLoggingCoverageIssues(ctx, cs)...)
	issues = append(issues, alertCoverageIssues(deployments.Items, daemonsets.Items, ruleCorpus)...)
	issues = append(issues, runtimeDetectionCoverageIssues(pods.Items, daemonsets.Items)...)
	issues = append(issues, driftAndIntegrityCoverageIssues(pods.Items, deployments.Items)...)
	return dedupeIssues(issues), nil
}

func auditLoggingCoverageIssues(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	components, err := discoverControlPlaneComponents(ctx, cs)
	if err != nil {
		return nil
	}
	pod := firstComponentPod(components["kube-apiserver"])
	if pod == nil {
		return nil
	}
	flags := collectContainerFlags(*pod)
	if firstFlagValue(flags, "audit-log-path") != "" && firstFlagValue(flags, "audit-policy-file") != "" {
		return nil
	}
	return []Issue{{
		Kind:           "APIServer",
		Namespace:      metav1.NamespaceSystem,
		Name:           pod.Name,
		Severity:       SeverityCritical,
		Category:       "security",
		Check:          "observability-audit-logs-missing",
		Summary:        "audit logging is not fully configured on the API server",
		Recommendation: "Configure audit-log-path and audit-policy-file so security-relevant actions such as RBAC changes, secret access, and exec/attach can be detected and investigated.",
	}}
}

func alertCoverageIssues(deployments []appsv1.Deployment, daemonsets []appsv1.DaemonSet, ruleCorpus string) []Issue {
	monitoringPresent := hasMonitoringStack(deployments, daemonsets)
	issues := make([]Issue, 0)
	if !monitoringPresent {
		issues = append(issues, Issue{
			Kind:           "ControlPlane",
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "observability-alerting-missing",
			Summary:        "no obvious in-cluster monitoring or alerting stack was detected",
			Recommendation: "Deploy or integrate cluster alerting so RBAC changes, privileged workloads, webhook failures, and policy drift create actionable signals.",
		})
		return issues
	}
	categories := []struct {
		check   string
		summary string
		markers []string
	}{
		{"observability-rbac-alerts", "no obvious alert coverage for RBAC or ClusterRoleBinding changes", []string{"clusterrolebinding", "rolebinding", "clusterrole", "rbac"}},
		{"observability-privileged-pod-alerts", "no obvious alert coverage for new privileged pods", []string{"privileged", "hostpath", "runasroot", "pod_security", "securitycontext"}},
		{"observability-exec-alerts", "no obvious alert coverage for exec/attach/port-forward activity", []string{"pods/exec", "exec", "attach", "port-forward", "portforward"}},
		{"observability-secret-alerts", "no obvious alert coverage for secret reads or spikes", []string{"secret", "get secrets", "watch secrets", "apiserver_request_total"}},
		{"observability-webhook-alerts", "no obvious alert coverage for webhook failures or policy bypass", []string{"webhook", "admission", "failurepolicy", "policy bypass"}},
	}
	text := strings.ToLower(ruleCorpus)
	for _, category := range categories {
		if containsAny(text, category.markers) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "ControlPlane",
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          category.check,
			Summary:        category.summary,
			Recommendation: "Add alert rules for this security-relevant control-plane activity so operators get notified before drift turns into a breach or outage.",
		})
	}
	return issues
}

func runtimeDetectionCoverageIssues(pods []corev1.Pod, daemonsets []appsv1.DaemonSet) []Issue {
	markers := []string{"falco", "tetragon", "hubble", "cilium", "tracee", "sysdig"}
	if workloadSetContains(pods, daemonsets, markers) {
		return nil
	}
	return []Issue{{
		Kind:           "DaemonSet",
		Severity:       SeverityWarning,
		Category:       "security",
		Check:          "observability-runtime-detection-missing",
		Summary:        "no obvious runtime detection tooling such as Falco, Tetragon, or Hubble was detected",
		Recommendation: "Deploy runtime detection or flow-visibility tooling so suspicious exec, egress, and privilege escalation behavior can be observed promptly.",
	}}
}

func driftAndIntegrityCoverageIssues(pods []corev1.Pod, deployments []appsv1.Deployment) []Issue {
	issues := make([]Issue, 0)
	if !workloadSetContainsPodsAndDeployments(pods, deployments, []string{"argocd", "argo-cd", "flux", "fleet", "kapp", "gitops"}) {
		issues = append(issues, Issue{
			Kind:           "Deployment",
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "observability-drift-detection-missing",
			Summary:        "no obvious drift detection or GitOps reconciliation controller was detected",
			Recommendation: "Use GitOps or equivalent drift detection so unexpected security changes in manifests and policies are detected quickly.",
		})
	}
	if !workloadSetContainsPodsAndDeployments(pods, deployments, []string{"kyverno", "gatekeeper", "opa", "conftest", "policy"}) {
		issues = append(issues, Issue{
			Kind:           "Deployment",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "observability-integrity-monitoring-missing",
			Summary:        "no obvious manifest integrity or policy controller was detected",
			Recommendation: "Use policy engines and manifest integrity controls so unauthorized changes to manifests and admission policy are visible and reviewable.",
		})
	}
	return issues
}

func collectAlertRuleCorpus(ctx context.Context, dyn dynamic.Interface, namespace string, configMaps []corev1.ConfigMap) string {
	parts := make([]string, 0)
	for _, configMap := range configMaps {
		text := strings.ToLower(configMap.Name + " " + strings.Join(mapValues(configMap.Data), " "))
		if containsAny(text, []string{"alert", "rule", "prometheus", "alertmanager"}) {
			parts = append(parts, text)
		}
	}
	if dyn != nil {
		rules, err := dyn.Resource(prometheusRuleGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, rule := range rules.Items {
				parts = append(parts, strings.ToLower(rule.GetName()))
				parts = append(parts, strings.ToLower(fmt.Sprintf("%v", rule.Object["spec"])))
			}
		}
	}
	return strings.Join(parts, "\n")
}

func hasMonitoringStack(deployments []appsv1.Deployment, daemonsets []appsv1.DaemonSet) bool {
	markers := []string{"prometheus", "alertmanager", "victoria", "grafana", "datadog", "newrelic", "splunk", "loki"}
	for _, deployment := range deployments {
		if containsAny(strings.ToLower(deployment.Namespace+"/"+deployment.Name), markers) {
			return true
		}
	}
	for _, daemonset := range daemonsets {
		if containsAny(strings.ToLower(daemonset.Namespace+"/"+daemonset.Name), markers) {
			return true
		}
	}
	return false
}

func workloadSetContains(pods []corev1.Pod, daemonsets []appsv1.DaemonSet, markers []string) bool {
	for _, pod := range pods {
		if containsAny(strings.ToLower(pod.Namespace+"/"+pod.Name), markers) {
			return true
		}
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			if containsAny(strings.ToLower(container.Name+" "+container.Image), markers) {
				return true
			}
		}
	}
	for _, daemonset := range daemonsets {
		if containsAny(strings.ToLower(daemonset.Namespace+"/"+daemonset.Name), markers) {
			return true
		}
	}
	return false
}

func workloadSetContainsPodsAndDeployments(pods []corev1.Pod, deployments []appsv1.Deployment, markers []string) bool {
	for _, pod := range pods {
		if containsAny(strings.ToLower(pod.Namespace+"/"+pod.Name), markers) {
			return true
		}
	}
	for _, deployment := range deployments {
		if containsAny(strings.ToLower(deployment.Namespace+"/"+deployment.Name), markers) {
			return true
		}
		for _, container := range deployment.Spec.Template.Spec.Containers {
			if containsAny(strings.ToLower(container.Name+" "+container.Image), markers) {
				return true
			}
		}
	}
	return false
}
