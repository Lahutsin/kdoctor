package diagnostics

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckPolicyCompliance(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}
	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	deployments, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	statefulSets, err := cs.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	daemonsets, err := cs.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pdbs, err := cs.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		pdbs = &policyv1.PodDisruptionBudgetList{}
	}
	networkPolicies, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	issues := make([]Issue, 0)
	issues = append(issues, requiredMetadataIssues(namespaces, deployments.Items, statefulSets.Items, daemonsets.Items)...)
	issues = append(issues, mandatorySecurityContextIssues(pods.Items, namespaces)...)
	issues = append(issues, mandatoryNetworkPolicyIssues(pods.Items, namespaces, networkPolicies.Items)...)
	issues = append(issues, mandatoryPDBIssues(deployments.Items, statefulSets.Items, pdbs.Items, namespaces)...)
	issues = append(issues, mandatoryResourceRequestsIssues(pods.Items, namespaces)...)
	issues = append(issues, complianceBaselineIssues(ctx, cs, namespaces, pods.Items, networkPolicies.Items)...)
	issues = append(issues, deprecatedAPIComplianceIssues(ctx, cs)...)
	issues = append(issues, exceptionsRegistryIssues(namespaces, deployments.Items, statefulSets.Items, daemonsets.Items)...)
	return dedupeIssues(issues), nil
}

func requiredMetadataIssues(namespaces map[string]namespaceMeta, deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonsets []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	for _, ns := range sortedNamespaceMeta(namespaces) {
		if looksLikeSystemNamespace(ns.name) {
			continue
		}
		if hasRequiredOwnershipMetadata(ns.labels, ns.annotations) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Namespace",
			Name:           ns.name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-required-metadata",
			Summary:        "namespace is missing ownership or classification metadata",
			Recommendation: "Require owner/team and data-classification metadata on namespaces so security exceptions and incident handling have clear accountability.",
		})
	}
	for _, issue := range workloadMetadataIssues("Deployment", deployments) {
		issues = append(issues, issue)
	}
	for _, issue := range statefulSetMetadataIssues(statefulSets) {
		issues = append(issues, issue)
	}
	for _, issue := range daemonSetMetadataIssues(daemonsets) {
		issues = append(issues, issue)
	}
	return issues
}

func mandatorySecurityContextIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if !isSensitiveWorkload(pod, namespaces[pod.Namespace]) {
			continue
		}
		missingScopes := make([]string, 0, 2)
		if pod.Spec.SecurityContext == nil {
			missingScopes = append(missingScopes, "pod")
		}
		missingContainers := make([]string, 0)
		for _, container := range allSecurityContainers(pod) {
			if container.securityContext == nil {
				missingContainers = append(missingContainers, container.name)
			}
		}
		if len(missingContainers) == 0 && len(missingScopes) == 0 {
			continue
		}
		if len(missingContainers) > 0 {
			missingScopes = append(missingScopes, fmt.Sprintf("containers=%s", strings.Join(uniqueStrings(missingContainers), ",")))
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-securitycontext-required",
			Summary:        fmt.Sprintf("sensitive workload lacks explicit securityContext settings for %s", strings.Join(missingScopes, "; ")),
			Recommendation: "Require securityContext defaults such as runAsNonRoot, seccompProfile, and allowPrivilegeEscalation=false for sensitive workloads.",
		})
	}
	return issues
}

func mandatoryNetworkPolicyIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta, policies []networkingv1.NetworkPolicy) []Issue {
	podsByNS := map[string][]corev1.Pod{}
	policiesByNS := map[string][]networkingv1.NetworkPolicy{}
	for _, pod := range pods {
		podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
	}
	for _, policy := range policies {
		policiesByNS[policy.Namespace] = append(policiesByNS[policy.Namespace], policy)
	}
	issues := make([]Issue, 0)
	for _, ns := range sortedNamespaceMeta(namespaces) {
		if len(podsByNS[ns.name]) == 0 || looksLikeSystemNamespace(ns.name) {
			continue
		}
		if len(policiesByNS[ns.name]) > 0 {
			continue
		}
		severity := SeverityInfo
		if isProductionNamespace(ns) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "Namespace",
			Name:           ns.name,
			Severity:       severity,
			Category:       "security",
			Check:          "policy-networkpolicy-required",
			Summary:        "namespace has workloads but no NetworkPolicies",
			Recommendation: "Treat network policies as mandatory for application namespaces, especially in production and tenant-isolated environments.",
		})
	}
	return issues
}

func mandatoryPDBIssues(deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, pdbs []policyv1.PodDisruptionBudget, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, deployment := range deployments {
		if !controllerNeedsPDB(deployment.Namespace, deployment.Name, pointerInt32(deployment.Spec.Replicas), deployment.Spec.Selector.MatchLabels, namespaces, pdbs) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Deployment",
			Namespace:      deployment.Namespace,
			Name:           deployment.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-pdb-required",
			Summary:        "critical deployment lacks a matching PodDisruptionBudget",
			Recommendation: "Define a PDB for multi-replica critical workloads so voluntary disruptions do not create avoidable outages.",
		})
	}
	for _, statefulSet := range statefulSets {
		if !controllerNeedsPDB(statefulSet.Namespace, statefulSet.Name, pointerInt32(statefulSet.Spec.Replicas), statefulSet.Spec.Selector.MatchLabels, namespaces, pdbs) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "StatefulSet",
			Namespace:      statefulSet.Namespace,
			Name:           statefulSet.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-pdb-required",
			Summary:        "critical stateful workload lacks a matching PodDisruptionBudget",
			Recommendation: "Define a PDB for critical stateful workloads so node drains and rolling updates do not violate availability expectations.",
		})
	}
	return issues
}

func mandatoryResourceRequestsIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if !isSensitiveWorkload(pod, namespaces[pod.Namespace]) && !isProductionNamespace(namespaces[pod.Namespace]) {
			continue
		}
		missing := make([]string, 0)
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			if container.Resources.Requests == nil || container.Resources.Limits == nil || container.Resources.Requests.Cpu().IsZero() || container.Resources.Requests.Memory().IsZero() || container.Resources.Limits.Cpu().IsZero() || container.Resources.Limits.Memory().IsZero() {
				missing = append(missing, container.Name)
			}
		}
		if len(missing) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-resource-requests-required",
			Summary:        fmt.Sprintf("containers are missing CPU/memory requests or limits: %s", strings.Join(uniqueStrings(missing), ", ")),
			Recommendation: "Require CPU and memory requests/limits for critical workloads so noisy neighbors and eviction behavior do not undermine isolation and availability.",
		})
	}
	return issues
}

func complianceBaselineIssues(ctx context.Context, cs *kubernetes.Clientset, namespaces map[string]namespaceMeta, pods []corev1.Pod, policies []networkingv1.NetworkPolicy) []Issue {
	issues := make([]Issue, 0)
	missingRestricted := 0
	for _, ns := range namespaces {
		if looksLikeSystemNamespace(ns.name) {
			continue
		}
		if psaLevel(ns.labels, "enforce") != "restricted" {
			missingRestricted++
		}
	}
	if missingRestricted > 0 {
		issues = append(issues, Issue{
			Kind:           "Namespace",
			Name:           "cis-nsa-baseline",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "policy-baseline-gap",
			Summary:        fmt.Sprintf("%d namespaces do not enforce restricted Pod Security, leaving CIS/NSA-style hardening incomplete", missingRestricted),
			Recommendation: "Treat restricted Pod Security, least-privilege runtime settings, and default-deny networking as part of the cluster baseline rather than optional improvements.",
		})
	}
	if len(inspectDeprecatedAPIs(ctx, cs)) > 0 {
		issues = append(issues, Issue{
			Kind:           "APIServer",
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-deprecated-apis",
			Summary:        "deprecated APIs are still in use, which is inconsistent with common hardening baselines",
			Recommendation: "Migrate away from deprecated APIs so security baselines and upgrade-readiness controls stay current.",
		})
	}
	_ = pods
	_ = policies
	return issues
}

func deprecatedAPIComplianceIssues(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	base := inspectDeprecatedAPIs(ctx, cs)
	issues := make([]Issue, 0, len(base))
	for _, issue := range base {
		issue.Check = "policy-deprecated-api-usage"
		issue.Recommendation = "Remove deprecated API consumers and keep cluster manifests aligned with currently supported API versions."
		issues = append(issues, issue)
	}
	return issues
}

func exceptionsRegistryIssues(namespaces map[string]namespaceMeta, deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonsets []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	for _, ns := range namespaces {
		if !hasExceptionMarkers(ns.labels, ns.annotations) || hasExceptionMetadata(ns.labels, ns.annotations) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Namespace",
			Name:           ns.name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "policy-exception-registry",
			Summary:        "namespace declares a security exception without owner/reason/expiry metadata",
			Recommendation: "Track exceptions with who approved them, why they exist, and until when they remain valid.",
		})
	}
	for _, issue := range controllerExceptionIssues(deployments, statefulSets, daemonsets) {
		issues = append(issues, issue)
	}
	return issues
}

func hasRequiredOwnershipMetadata(labels, annotations map[string]string) bool {
	owner := hasMetadataKey(labels, annotations, []string{"owner", "team", "service-owner", "responsible"})
	classification := hasMetadataKey(labels, annotations, []string{"classification", "data-classification", "sensitivity", "tier"})
	return owner && classification
}

func hasMetadataKey(labels, annotations map[string]string, keys []string) bool {
	for _, source := range []map[string]string{labels, annotations} {
		for key, value := range source {
			keyLower := strings.ToLower(key)
			if strings.TrimSpace(value) == "" {
				continue
			}
			for _, expected := range keys {
				if strings.Contains(keyLower, expected) {
					return true
				}
			}
		}
	}
	return false
}

func workloadMetadataIssues(kind string, deployments []appsv1.Deployment) []Issue {
	issues := make([]Issue, 0)
	for _, deployment := range deployments {
		if hasRequiredOwnershipMetadata(deployment.Labels, deployment.Annotations) {
			continue
		}
		issues = append(issues, Issue{Kind: kind, Namespace: deployment.Namespace, Name: deployment.Name, Severity: SeverityInfo, Category: "security", Check: "policy-required-metadata", Summary: strings.ToLower(kind) + " is missing ownership or classification metadata", Recommendation: "Add owner/team and data-classification metadata to workload controllers so policy exceptions and operational responsibility are explicit."})
	}
	return issues
}

func statefulSetMetadataIssues(items []appsv1.StatefulSet) []Issue {
	issues := make([]Issue, 0)
	for _, item := range items {
		if hasRequiredOwnershipMetadata(item.Labels, item.Annotations) {
			continue
		}
		issues = append(issues, Issue{Kind: "StatefulSet", Namespace: item.Namespace, Name: item.Name, Severity: SeverityInfo, Category: "security", Check: "policy-required-metadata", Summary: "statefulset is missing ownership or classification metadata", Recommendation: "Add owner/team and data-classification metadata to workload controllers so policy exceptions and operational responsibility are explicit."})
	}
	return issues
}

func daemonSetMetadataIssues(items []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	for _, item := range items {
		if hasRequiredOwnershipMetadata(item.Labels, item.Annotations) {
			continue
		}
		issues = append(issues, Issue{Kind: "DaemonSet", Namespace: item.Namespace, Name: item.Name, Severity: SeverityInfo, Category: "security", Check: "policy-required-metadata", Summary: "daemonset is missing ownership or classification metadata", Recommendation: "Add owner/team and data-classification metadata to workload controllers so policy exceptions and operational responsibility are explicit."})
	}
	return issues
}

func controllerNeedsPDB(namespace, name string, replicas *int32, selector map[string]string, namespaces map[string]namespaceMeta, pdbs []policyv1.PodDisruptionBudget) bool {
	if replicas == nil || *replicas < 2 || !isProductionNamespace(namespaces[namespace]) {
		return false
	}
	for _, pdb := range pdbs {
		if pdb.Namespace != namespace || pdb.Spec.Selector == nil {
			continue
		}
		matches := true
		for key, value := range selector {
			if pdb.Spec.Selector.MatchLabels[key] != value {
				matches = false
				break
			}
		}
		if matches {
			return false
		}
	}
	_ = name
	return true
}

func pointerInt32(value *int32) *int32 {
	return value
}

func hasExceptionMarkers(labels, annotations map[string]string) bool {
	for _, source := range []map[string]string{labels, annotations} {
		for key := range source {
			text := strings.ToLower(key)
			if strings.Contains(text, "exception") || strings.Contains(text, "waiver") || strings.Contains(text, "risk-accept") {
				return true
			}
		}
	}
	return false
}

func hasExceptionMetadata(labels, annotations map[string]string) bool {
	return hasMetadataKey(labels, annotations, []string{"owner", "approver", "ticket"}) && hasMetadataKey(labels, annotations, []string{"reason", "justification"}) && hasMetadataKey(labels, annotations, []string{"expires", "until", "review-by"})
}

func controllerExceptionIssues(deployments []appsv1.Deployment, statefulSets []appsv1.StatefulSet, daemonsets []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	for _, deployment := range deployments {
		if hasExceptionMarkers(deployment.Labels, deployment.Annotations) && !hasExceptionMetadata(deployment.Labels, deployment.Annotations) {
			issues = append(issues, Issue{Kind: "Deployment", Namespace: deployment.Namespace, Name: deployment.Name, Severity: SeverityWarning, Category: "security", Check: "policy-exception-registry", Summary: "deployment has a security exception without full owner/reason/expiry metadata", Recommendation: "Track workload exceptions with owner, reason, and expiry so security drift does not become permanent by accident."})
		}
	}
	for _, statefulSet := range statefulSets {
		if hasExceptionMarkers(statefulSet.Labels, statefulSet.Annotations) && !hasExceptionMetadata(statefulSet.Labels, statefulSet.Annotations) {
			issues = append(issues, Issue{Kind: "StatefulSet", Namespace: statefulSet.Namespace, Name: statefulSet.Name, Severity: SeverityWarning, Category: "security", Check: "policy-exception-registry", Summary: "statefulset has a security exception without full owner/reason/expiry metadata", Recommendation: "Track workload exceptions with owner, reason, and expiry so security drift does not become permanent by accident."})
		}
	}
	for _, daemonset := range daemonsets {
		if hasExceptionMarkers(daemonset.Labels, daemonset.Annotations) && !hasExceptionMetadata(daemonset.Labels, daemonset.Annotations) {
			issues = append(issues, Issue{Kind: "DaemonSet", Namespace: daemonset.Namespace, Name: daemonset.Name, Severity: SeverityWarning, Category: "security", Check: "policy-exception-registry", Summary: "daemonset has a security exception without full owner/reason/expiry metadata", Recommendation: "Track workload exceptions with owner, reason, and expiry so security drift does not become permanent by accident."})
		}
	}
	return issues
}
