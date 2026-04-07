package diagnostics

import (
	"context"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func CheckNetworkSecurity(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
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
	policies, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	webhookSvcs, err := referencedWebhookServices(ctx, cs)
	if err != nil {
		return nil, err
	}

	policiesByNS := map[string][]networkingv1.NetworkPolicy{}
	podsByNS := map[string][]corev1.Pod{}
	for _, policy := range policies.Items {
		policiesByNS[policy.Namespace] = append(policiesByNS[policy.Namespace], policy)
	}
	for _, pod := range pods.Items {
		podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
	}

	issues := make([]Issue, 0)
	for nsName, nsMeta := range namespaces {
		nsPolicies := policiesByNS[nsName]
		nsPods := podsByNS[nsName]
		needsIsolation := namespaceNeedsIsolation(nsMeta, nsPods)
		if len(nsPolicies) == 0 {
			severity := SeverityInfo
			if needsIsolation {
				severity = SeverityWarning
			}
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           nsName,
				Severity:       severity,
				Category:       "security",
				Check:          "networkpolicy-missing",
				Summary:        "namespace has no NetworkPolicy resources",
				Recommendation: "Add NetworkPolicies to define expected ingress and egress paths instead of relying on the cluster default allow behavior.",
			})
		} else if needsIsolation {
			if !namespaceHasDefaultDeny(nsPolicies, networkingv1.PolicyTypeIngress) {
				issues = append(issues, Issue{
					Kind:           "Namespace",
					Name:           nsName,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "networkpolicy-default-deny-ingress",
					Summary:        "namespace lacks a default deny ingress NetworkPolicy",
					Recommendation: "Add a namespace-wide default deny ingress policy, then explicitly allow only the expected sources.",
				})
			}
			if !namespaceHasDefaultDeny(nsPolicies, networkingv1.PolicyTypeEgress) {
				issues = append(issues, Issue{
					Kind:           "Namespace",
					Name:           nsName,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "networkpolicy-default-deny-egress",
					Summary:        "namespace lacks a default deny egress NetworkPolicy",
					Recommendation: "Add a namespace-wide default deny egress policy, then allow only required destinations such as DNS, webhooks, and external APIs.",
				})
			}
		}
		issues = append(issues, broadPolicyIssues(nsPolicies)...)
		issues = append(issues, sensitiveWorkloadExposureIssues(nsPods, nsMeta, nsPolicies)...)
	}

	issues = append(issues, webhookNetworkRestrictionIssues(webhookSvcs, policiesByNS, podsByNS)...)
	issues = append(issues, ingressControllerExposureIssues(services.Items)...)
	issues = append(issues, loadBalancerExposureIssues(services.Items)...)

	return dedupeIssues(issues), nil
}

func namespaceNeedsIsolation(ns namespaceMeta, pods []corev1.Pod) bool {
	if isProductionNamespace(ns) {
		return true
	}
	if looksLikeSystemNamespace(ns.name) {
		return true
	}
	for _, pod := range pods {
		if isSensitiveWorkload(pod, ns) || podConsumesSecrets(pod) {
			return true
		}
	}
	return false
}

func namespaceHasDefaultDeny(policies []networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	for _, policy := range policies {
		if len(policy.Spec.PodSelector.MatchLabels) != 0 || len(policy.Spec.PodSelector.MatchExpressions) != 0 {
			continue
		}
		if !policyCoversType(policy, policyType) {
			continue
		}
		if policyType == networkingv1.PolicyTypeIngress && len(policy.Spec.Ingress) == 0 {
			return true
		}
		if policyType == networkingv1.PolicyTypeEgress && len(policy.Spec.Egress) == 0 {
			return true
		}
	}
	return false
}

func broadPolicyIssues(policies []networkingv1.NetworkPolicy) []Issue {
	issues := make([]Issue, 0)
	for _, policy := range policies {
		if policyAllowsAllIngress(policy) {
			issues = append(issues, Issue{
				Kind:           "NetworkPolicy",
				Namespace:      policy.Namespace,
				Name:           policy.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "networkpolicy-broad-ingress",
				Summary:        "network policy has overly broad ingress rules",
				Recommendation: "Avoid open ingress sources like all namespaces, all pods, or 0.0.0.0/0 unless the workload is intentionally public and separately protected.",
			})
		}
		if policyAllowsAllEgress(policy) {
			issues = append(issues, Issue{
				Kind:           "NetworkPolicy",
				Namespace:      policy.Namespace,
				Name:           policy.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "networkpolicy-broad-egress",
				Summary:        "network policy has overly broad egress rules",
				Recommendation: "Replace allow-all egress with explicit destinations and ports, especially for namespaces handling secrets or internet-facing workloads.",
			})
		}
	}
	return issues
}

func sensitiveWorkloadExposureIssues(pods []corev1.Pod, ns namespaceMeta, policies []networkingv1.NetworkPolicy) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if !isSensitiveWorkload(pod, ns) {
			continue
		}
		ingressPolicies := selectingPoliciesForPod(policies, pod, networkingv1.PolicyTypeIngress)
		egressPolicies := selectingPoliciesForPod(policies, pod, networkingv1.PolicyTypeEgress)
		if len(ingressPolicies) == 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "networkpolicy-sensitive-ingress",
				Summary:        "sensitive workload has no ingress NetworkPolicy protection",
				Recommendation: "Add ingress NetworkPolicies so sensitive workloads are reachable only from the exact namespaces, pods, and ports that need access.",
			})
		} else if policiesAllowAllIngress(ingressPolicies) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "networkpolicy-sensitive-all-namespaces",
				Summary:        "sensitive workload is reachable from all namespaces or broadly selected sources",
				Recommendation: "Tighten ingress peers for this workload so only trusted namespaces and pod selectors can initiate connections.",
			})
		}
		if podConsumesSecrets(pod) && len(egressPolicies) == 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "networkpolicy-secret-egress",
				Summary:        "workload with access to secrets has unrestricted egress",
				Recommendation: "Constrain egress for workloads that handle secrets so they can reach only required services, DNS, and external APIs.",
			})
		} else if podConsumesSecrets(pod) && policiesAllowAllEgress(egressPolicies) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "networkpolicy-secret-egress",
				Summary:        "workload with access to secrets is covered only by overly broad egress rules",
				Recommendation: "Replace broad egress policies with explicit destinations so secret-bearing workloads cannot exfiltrate data arbitrarily.",
			})
		}
		if hasOpenDNSEgress(egressPolicies) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "networkpolicy-dns-open-egress",
				Summary:        "DNS egress is allowed broadly rather than only to cluster DNS endpoints",
				Recommendation: "Restrict DNS egress to the in-cluster DNS service or resolver IPs instead of allowing port 53 to arbitrary destinations.",
			})
		}
		if len(egressPolicies) == 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "networkpolicy-controlplane-egress",
				Summary:        "pod-to-control-plane and external egress are not restricted by NetworkPolicy",
				Recommendation: "Constrain egress from sensitive workloads so they can reach only required APIs and cluster services, including the control plane when necessary.",
			})
		}
	}
	return issues
}

func selectingPoliciesForPod(policies []networkingv1.NetworkPolicy, pod corev1.Pod, policyType networkingv1.PolicyType) []networkingv1.NetworkPolicy {
	selected := make([]networkingv1.NetworkPolicy, 0)
	for _, policy := range policies {
		if !policyCoversType(policy, policyType) {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(pod.Labels)) {
			selected = append(selected, policy)
		}
	}
	return selected
}

func policyCoversType(policy networkingv1.NetworkPolicy, policyType networkingv1.PolicyType) bool {
	if len(policy.Spec.PolicyTypes) == 0 {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
		return len(policy.Spec.Egress) > 0
	}
	for _, t := range policy.Spec.PolicyTypes {
		if t == policyType {
			return true
		}
	}
	return false
}

func policyAllowsAllIngress(policy networkingv1.NetworkPolicy) bool {
	if !policyCoversType(policy, networkingv1.PolicyTypeIngress) {
		return false
	}
	for _, rule := range policy.Spec.Ingress {
		if len(rule.From) == 0 {
			return true
		}
		for _, peer := range rule.From {
			if peerAllowsAll(peer) || peerAllowsAllNamespaces(peer) {
				return true
			}
		}
	}
	return false
}

func policyAllowsAllEgress(policy networkingv1.NetworkPolicy) bool {
	if !policyCoversType(policy, networkingv1.PolicyTypeEgress) {
		return false
	}
	for _, rule := range policy.Spec.Egress {
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if peerAllowsAll(peer) || peerAllowsAllNamespaces(peer) || ipBlockAllowsAll(peer.IPBlock) {
				return true
			}
		}
	}
	return false
}

func policiesAllowAllIngress(policies []networkingv1.NetworkPolicy) bool {
	for _, policy := range policies {
		if policyAllowsAllIngress(policy) {
			return true
		}
	}
	return false
}

func policiesAllowAllEgress(policies []networkingv1.NetworkPolicy) bool {
	for _, policy := range policies {
		if policyAllowsAllEgress(policy) {
			return true
		}
	}
	return false
}

func peerAllowsAll(peer networkingv1.NetworkPolicyPeer) bool {
	return peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.IPBlock == nil
}

func peerAllowsAllNamespaces(peer networkingv1.NetworkPolicyPeer) bool {
	if peer.NamespaceSelector == nil {
		return false
	}
	if len(peer.NamespaceSelector.MatchLabels) == 0 && len(peer.NamespaceSelector.MatchExpressions) == 0 {
		return true
	}
	return false
}

func ipBlockAllowsAll(block *networkingv1.IPBlock) bool {
	if block == nil {
		return false
	}
	cidr := strings.TrimSpace(block.CIDR)
	return (cidr == "0.0.0.0/0" || cidr == "::/0") && len(block.Except) == 0
}

func hasOpenDNSEgress(policies []networkingv1.NetworkPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Spec.Egress {
			if !ruleIncludesDNS(rule) {
				continue
			}
			if len(rule.To) == 0 {
				return true
			}
			for _, peer := range rule.To {
				if peerAllowsAll(peer) || peerAllowsAllNamespaces(peer) || ipBlockAllowsAll(peer.IPBlock) {
					return true
				}
			}
		}
	}
	return false
}

func ruleIncludesDNS(rule networkingv1.NetworkPolicyEgressRule) bool {
	for _, port := range rule.Ports {
		if port.Port == nil {
			continue
		}
		if port.Port.Type == 0 && (port.Port.IntValue() == 53 || port.Port.String() == "53") {
			return true
		}
		if strings.EqualFold(port.Port.String(), "domain") || strings.EqualFold(pointerProtocol(port.Protocol), "udp") && port.Port.IntValue() == 53 {
			return true
		}
	}
	return false
}

func referencedWebhookServices(ctx context.Context, cs *kubernetes.Clientset) (map[string]struct{}, error) {
	services := map[string]struct{}{}
	validating, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	mutating, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, cfg := range validating.Items {
		collectValidatingWebhookServiceRefs(services, cfg.Webhooks)
	}
	for _, cfg := range mutating.Items {
		collectMutatingWebhookServiceRefs(services, cfg.Webhooks)
	}
	return services, nil
}

func collectValidatingWebhookServiceRefs(target map[string]struct{}, webhooks []admissionv1.ValidatingWebhook) {
	for _, webhook := range webhooks {
		if webhook.ClientConfig.Service == nil {
			continue
		}
		target[webhook.ClientConfig.Service.Namespace+"/"+webhook.ClientConfig.Service.Name] = struct{}{}
	}
}

func collectMutatingWebhookServiceRefs(target map[string]struct{}, webhooks []admissionv1.MutatingWebhook) {
	for _, webhook := range webhooks {
		if webhook.ClientConfig.Service == nil {
			continue
		}
		target[webhook.ClientConfig.Service.Namespace+"/"+webhook.ClientConfig.Service.Name] = struct{}{}
	}
}

func webhookNetworkRestrictionIssues(webhookSvcs map[string]struct{}, policiesByNS map[string][]networkingv1.NetworkPolicy, podsByNS map[string][]corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for key := range webhookSvcs {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 {
			continue
		}
		ns, name := parts[0], parts[1]
		servicePodsProtected := false
		for _, policy := range policiesByNS[ns] {
			if policyCoversType(policy, networkingv1.PolicyTypeIngress) && (len(policy.Spec.PodSelector.MatchLabels) == 0 && len(policy.Spec.PodSelector.MatchExpressions) == 0 || policyReferencesSomePods(policy, podsByNS[ns])) {
				servicePodsProtected = true
				break
			}
		}
		if !servicePodsProtected {
			issues = append(issues, Issue{
				Kind:           "Webhook",
				Namespace:      ns,
				Name:           name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "webhook-networkpolicy-missing",
				Summary:        "webhook service namespace lacks obvious ingress network restrictions",
				Recommendation: "Add NetworkPolicies around webhook backends so only the API server or explicitly trusted callers can reach them.",
			})
		}
	}
	return issues
}

func policyReferencesSomePods(policy networkingv1.NetworkPolicy, pods []corev1.Pod) bool {
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		return false
	}
	for _, pod := range pods {
		if selector.Matches(labels.Set(pod.Labels)) {
			return true
		}
	}
	return false
}

func ingressControllerExposureIssues(services []corev1.Service) []Issue {
	issues := make([]Issue, 0)
	for _, service := range services {
		if !serviceExternallyReachable(service) {
			continue
		}
		if !looksLikeIngressController(service) {
			continue
		}
		ports := serviceDebugPorts(service)
		if len(ports) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Service",
			Namespace:      service.Namespace,
			Name:           service.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "ingress-controller-admin-ports",
			Summary:        fmt.Sprintf("externally reachable ingress controller exposes admin or metrics ports: %s", strings.Join(ports, ", ")),
			Recommendation: "Keep ingress controller metrics and admin ports internal or protected by strict network and authentication controls.",
		})
	}
	return issues
}

func loadBalancerExposureIssues(services []corev1.Service) []Issue {
	issues := make([]Issue, 0)
	for _, service := range services {
		if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if serviceHasAllowlist(service) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Service",
			Namespace:      service.Namespace,
			Name:           service.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "loadbalancer-public-no-allowlist",
			Summary:        "LoadBalancer service appears publicly exposed without source allowlist restrictions",
			Recommendation: "Restrict public LoadBalancer services with loadBalancerSourceRanges or cloud-provider allowlist annotations when broad internet exposure is not required.",
		})
	}
	return issues
}

func looksLikeIngressController(service corev1.Service) bool {
	fields := []string{service.Name}
	for key, value := range service.Labels {
		fields = append(fields, key, value)
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"ingress", "nginx", "traefik", "haproxy", "gateway"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func serviceHasAllowlist(service corev1.Service) bool {
	if len(service.Spec.LoadBalancerSourceRanges) > 0 {
		return true
	}
	for key, value := range service.Annotations {
		combined := strings.ToLower(key + "=" + value)
		for _, marker := range []string{"whitelist-source-range", "allowlist", "load-balancer-source-ranges", "loadBalancerSourceRanges", "scheme=internal", "internal-load-balancer"} {
			if strings.Contains(combined, strings.ToLower(marker)) {
				return true
			}
		}
	}
	return false
}

func podConsumesSecrets(pod corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			return true
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					return true
				}
			}
		}
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				return true
			}
		}
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil {
				return true
			}
		}
	}
	return false
}

func pointerProtocol(protocol *corev1.Protocol) string {
	if protocol == nil {
		return ""
	}
	return string(*protocol)
}
