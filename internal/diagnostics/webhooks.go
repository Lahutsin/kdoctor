package diagnostics

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type webhookInventory struct {
	services    map[string]corev1.Service
	endpoints   map[string]*corev1.Endpoints
	podsByNS    map[string][]corev1.Pod
	secretsByNS map[string][]corev1.Secret
	namespaces  map[string]namespaceMeta
}

type webhookEvaluation struct {
	kind                  string
	cfgName               string
	webhookName           string
	clientConfig          admissionv1.WebhookClientConfig
	failurePolicy         admissionv1.FailurePolicyType
	timeoutSeconds        int32
	rules                 []admissionv1.RuleWithOperations
	namespaceSelector     *metav1.LabelSelector
	objectSelector        *metav1.LabelSelector
	matchConditions       []admissionv1.MatchCondition
	reinvocationPolicy    *admissionv1.ReinvocationPolicyType
	sideEffects           *admissionv1.SideEffectClass
	admissionReviewVerses []string
}

// CheckWebhooks validates that webhook services are reachable and not misconfigured.
func CheckWebhooks(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}

	inventory, err := buildWebhookInventory(ctx, cs)
	if err != nil {
		return nil, err
	}

	var issues []Issue

	vcfgs, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		for _, cfg := range vcfgs.Items {
			issues = append(issues, evaluateValidatingWebhook(ctx, cs, inventory, cfg)...)
		}
	}

	mcfgs, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	if err == nil {
		for _, cfg := range mcfgs.Items {
			issues = append(issues, evaluateMutatingWebhook(ctx, cs, inventory, cfg)...)
		}
	}

	return dedupeIssues(issues), nil
}

func buildWebhookInventory(ctx context.Context, cs *kubernetes.Clientset) (webhookInventory, error) {
	namespaces, err := listNamespaceMeta(ctx, cs, "")
	if err != nil {
		return webhookInventory{}, err
	}
	services, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return webhookInventory{}, err
	}
	endpoints, err := cs.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return webhookInventory{}, err
	}
	pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return webhookInventory{}, err
	}
	secrets, err := cs.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return webhookInventory{}, err
	}

	inventory := webhookInventory{
		services:    make(map[string]corev1.Service, len(services.Items)),
		endpoints:   make(map[string]*corev1.Endpoints, len(endpoints.Items)),
		podsByNS:    make(map[string][]corev1.Pod),
		secretsByNS: make(map[string][]corev1.Secret),
		namespaces:  namespaces,
	}
	for _, service := range services.Items {
		inventory.services[service.Namespace+"/"+service.Name] = service
	}
	for _, endpoint := range endpoints.Items {
		ep := endpoint
		inventory.endpoints[endpoint.Namespace+"/"+endpoint.Name] = &ep
	}
	for _, pod := range pods.Items {
		inventory.podsByNS[pod.Namespace] = append(inventory.podsByNS[pod.Namespace], pod)
	}
	for _, secret := range secrets.Items {
		inventory.secretsByNS[secret.Namespace] = append(inventory.secretsByNS[secret.Namespace], secret)
	}
	return inventory, nil
}

func evaluateValidatingWebhook(ctx context.Context, cs *kubernetes.Clientset, inventory webhookInventory, cfg admissionv1.ValidatingWebhookConfiguration) []Issue {
	issues := make([]Issue, 0)
	for _, wh := range cfg.Webhooks {
		issues = append(issues, evaluateWebhook(ctx, cs, inventory, webhookEvaluation{
			kind:              "ValidatingWebhookConfiguration",
			cfgName:           cfg.Name,
			webhookName:       wh.Name,
			clientConfig:      wh.ClientConfig,
			failurePolicy:     effectiveFailurePolicy(wh.FailurePolicy),
			timeoutSeconds:    effectiveTimeoutSeconds(wh.TimeoutSeconds),
			rules:             wh.Rules,
			namespaceSelector: wh.NamespaceSelector,
			objectSelector:    wh.ObjectSelector,
			matchConditions:   wh.MatchConditions,
			sideEffects:       wh.SideEffects,
		})...)
	}
	return issues
}

func evaluateMutatingWebhook(ctx context.Context, cs *kubernetes.Clientset, inventory webhookInventory, cfg admissionv1.MutatingWebhookConfiguration) []Issue {
	issues := make([]Issue, 0)
	for _, wh := range cfg.Webhooks {
		issues = append(issues, evaluateWebhook(ctx, cs, inventory, webhookEvaluation{
			kind:               "MutatingWebhookConfiguration",
			cfgName:            cfg.Name,
			webhookName:        wh.Name,
			clientConfig:       wh.ClientConfig,
			failurePolicy:      effectiveFailurePolicy(wh.FailurePolicy),
			timeoutSeconds:     effectiveTimeoutSeconds(wh.TimeoutSeconds),
			rules:              wh.Rules,
			namespaceSelector:  wh.NamespaceSelector,
			objectSelector:     wh.ObjectSelector,
			matchConditions:    wh.MatchConditions,
			reinvocationPolicy: wh.ReinvocationPolicy,
			sideEffects:        wh.SideEffects,
		})...)
	}
	return issues
}

func evaluateWebhook(ctx context.Context, cs *kubernetes.Clientset, inventory webhookInventory, eval webhookEvaluation) []Issue {
	issues := make([]Issue, 0)
	if eval.clientConfig.URL != nil {
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-external-url",
			Summary:        fmt.Sprintf("webhook %s calls external URL %s", eval.webhookName, pointerString(eval.clientConfig.URL)),
			Recommendation: "Prefer in-cluster webhook services over direct external URLs so admission dependencies stay observable, isolated, and easier to secure.",
		})
	}
	if eval.clientConfig.Service == nil {
		return issues
	}

	svcNS := eval.clientConfig.Service.Namespace
	svcName := eval.clientConfig.Service.Name
	serviceKey := svcNS + "/" + svcName
	svc, found := inventory.services[serviceKey]
	if !found {
		_, err := cs.CoreV1().Services(svcNS).Get(ctx, svcName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			issues = append(issues, Issue{
				Kind:           eval.kind,
				Name:           eval.cfgName,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "webhook-service",
				Summary:        fmt.Sprintf("webhook %s service %s/%s missing", eval.webhookName, svcNS, svcName),
				Recommendation: "Deploy or fix the webhook service endpoints before keeping this admission dependency in the request path.",
			})
			return issues
		}
		if err != nil {
			issues = append(issues, Issue{
				Kind:           eval.kind,
				Name:           eval.cfgName,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "webhook-service",
				Summary:        fmt.Sprintf("webhook %s service lookup error: %v", eval.webhookName, err),
				Recommendation: "Check API access to webhook namespaces and service permissions.",
			})
			return issues
		}
	} else if serviceExternallyReachable(svc) {
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "webhook-service-exposed",
			Summary:        fmt.Sprintf("webhook %s service %s/%s is exposed beyond the cluster (%s)", eval.webhookName, svcNS, svcName, svc.Spec.Type),
			Recommendation: "Keep admission services cluster-internal only; remove NodePort/LoadBalancer exposure and external IPs from webhook backends.",
		})
	}

	readyEndpoints := true
	if eps, ok := inventory.endpoints[serviceKey]; ok {
		if !hasReadyAddress(eps) {
			readyEndpoints = false
			severity := SeverityWarning
			if eval.failurePolicy == admissionv1.Fail {
				severity = SeverityCritical
			}
			issues = append(issues, Issue{
				Kind:           eval.kind,
				Name:           eval.cfgName,
				Severity:       severity,
				Category:       "security",
				Check:          "webhook-endpoints",
				Summary:        fmt.Sprintf("webhook %s has no ready endpoints for service %s/%s", eval.webhookName, svcNS, svcName),
				Recommendation: "Ensure webhook pods are running and endpoints are populated; check network policies, readiness probes, and rollout health before keeping this webhook active.",
			})
		}
	}

	if eval.clientConfig.CABundle == nil || len(eval.clientConfig.CABundle) == 0 {
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-cabundle",
			Summary:        fmt.Sprintf("webhook %s missing caBundle", eval.webhookName),
			Recommendation: "Populate caBundle or enable cert management to avoid TLS errors to the webhook service.",
		})
	}
	issues = append(issues, webhookCABundleIssues(eval)...)
	issues = append(issues, webhookServingCertificateIssues(eval, svc, inventory)...)
	issues = append(issues, webhookFailurePolicyIssues(eval, readyEndpoints)...)
	issues = append(issues, broadWebhookRuleIssues(eval)...)
	issues = append(issues, sensitiveWebhookControlIssues(eval)...)
	issues = append(issues, mutatingSecurityContextIssues(eval)...)

	if eval.timeoutSeconds > 10 {
		severity := SeverityWarning
		if eval.timeoutSeconds > 20 {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       severity,
			Category:       "security",
			Check:          "webhook-timeout",
			Summary:        fmt.Sprintf("webhook %s timeoutSeconds=%d is high for an admission dependency", eval.webhookName, eval.timeoutSeconds),
			Recommendation: "Lower timeoutSeconds to 10s or less unless the webhook is strictly fail-open and the backend is consistently fast.",
		})
	} else if eval.timeoutSeconds == 10 {
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "webhook-timeout",
			Summary:        fmt.Sprintf("webhook %s relies on the default 10s timeout", eval.webhookName),
			Recommendation: "Set explicit timeoutSeconds so admission behavior is deliberate and easy to audit.",
		})
	}

	issues = append(issues, probeWebhookLatency(ctx, cs, svcNS, svcName)...)

	return issues
}

func effectiveFailurePolicy(policy *admissionv1.FailurePolicyType) admissionv1.FailurePolicyType {
	if policy == nil {
		return admissionv1.Fail
	}
	return *policy
}

func effectiveTimeoutSeconds(timeoutSeconds *int32) int32 {
	if timeoutSeconds == nil || *timeoutSeconds <= 0 {
		return 10
	}
	return *timeoutSeconds
}

func webhookCABundleIssues(eval webhookEvaluation) []Issue {
	if len(eval.clientConfig.CABundle) == 0 {
		return nil
	}
	issues := make([]Issue, 0)
	for _, cert := range parsePEMCertificates(eval.clientConfig.CABundle) {
		remaining := time.Until(cert.NotAfter)
		if remaining > 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "webhook-cert-expired",
			Summary:        fmt.Sprintf("webhook %s caBundle is expired (CN=%s, notAfter=%s)", eval.webhookName, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
			Recommendation: "Rotate the webhook CA bundle and the serving certificate chain together before admission traffic fails.",
		})
	}
	return issues
}

func webhookServingCertificateIssues(eval webhookEvaluation, service corev1.Service, inventory webhookInventory) []Issue {
	if service.Name == "" {
		return nil
	}
	pods := serviceSelectedPods(service, inventory.podsByNS[service.Namespace])
	if len(pods) == 0 {
		return nil
	}
	serviceNames := webhookServiceDNSNames(service)
	secretFindings := map[string][]Issue{}
	for _, pod := range pods {
		for _, secretName := range podReferencedSecrets(pod) {
			for _, secret := range inventory.secretsByNS[service.Namespace] {
				if secret.Name != secretName || len(secret.Data["tls.crt"]) == 0 {
					continue
				}
				if !secretLooksLikeWebhookCertificate(secret, serviceNames) {
					continue
				}
				for _, cert := range parsePEMCertificates(secret.Data["tls.crt"]) {
					if cert == nil || time.Until(cert.NotAfter) > 0 {
						continue
					}
					secretFindings[secret.Name] = append(secretFindings[secret.Name], Issue{
						Kind:           eval.kind,
						Name:           eval.cfgName,
						Severity:       SeverityCritical,
						Category:       "security",
						Check:          "webhook-cert-expired",
						Summary:        fmt.Sprintf("webhook %s appears to use expired serving certificate secret %s (CN=%s, notAfter=%s)", eval.webhookName, secret.Name, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
						Recommendation: "Rotate the webhook serving certificate secret and reload or restart the webhook pods so admission traffic uses fresh TLS material.",
					})
				}
			}
		}
	}
	issues := make([]Issue, 0)
	for _, findings := range secretFindings {
		issues = append(issues, findings...)
	}
	return issues
}

func webhookFailurePolicyIssues(eval webhookEvaluation, readyEndpoints bool) []Issue {
	issues := make([]Issue, 0)
	if eval.failurePolicy == admissionv1.Ignore && webhookNeedsEnforcement(eval) {
		severity := SeverityWarning
		if webhookTouchesSensitiveAdminResources(eval.rules) || webhookTouchesSecurityResources(eval.rules) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       severity,
			Category:       "security",
			Check:          "webhook-failure-policy-ignore",
			Summary:        fmt.Sprintf("webhook %s is fail-open even though it appears to enforce security-sensitive admission rules", eval.webhookName),
			Recommendation: "Use failurePolicy=Fail for security, policy, secret, RBAC, or identity enforcement webhooks where bypass on outage is not acceptable.",
		})
	}
	if eval.failurePolicy == admissionv1.Fail && webhookHasHighDoSRisk(eval, readyEndpoints) {
		issues = append(issues, Issue{
			Kind:           eval.kind,
			Name:           eval.cfgName,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-failure-policy-dos-risk",
			Summary:        fmt.Sprintf("webhook %s is fail-closed with broad scope and availability-sensitive settings", eval.webhookName),
			Recommendation: "Reduce DoS risk by narrowing webhook rules, adding selectors, lowering timeouts, and using failurePolicy=Ignore for non-critical or best-effort admission logic.",
		})
	}
	return issues
}

func broadWebhookRuleIssues(eval webhookEvaluation) []Issue {
	findings := make([]string, 0)
	for _, rule := range eval.rules {
		parts := make([]string, 0)
		if containsOperation(rule.Operations, admissionv1.OperationAll) || len(rule.Operations) == 0 {
			parts = append(parts, "operations=*")
		}
		if hasWildcard(rule.Rule.APIGroups) {
			parts = append(parts, "apiGroups=*")
		}
		if hasWildcard(rule.Rule.Resources) {
			parts = append(parts, "resources=*")
		}
		if rule.Rule.Scope == nil {
			parts = append(parts, "scope=all")
		}
		if len(parts) > 0 {
			findings = append(findings, strings.Join(parts, "/"))
		}
	}
	if len(findings) == 0 {
		return nil
	}
	severity := SeverityWarning
	if strings.Contains(eval.kind, "Mutating") {
		severity = SeverityCritical
	}
	return []Issue{{
		Kind:           eval.kind,
		Name:           eval.cfgName,
		Severity:       severity,
		Category:       "security",
		Check:          "webhook-rules-broad",
		Summary:        fmt.Sprintf("webhook %s uses overly broad admission rules: %s", eval.webhookName, strings.Join(uniqueStrings(findings), ", ")),
		Recommendation: "Restrict webhook rules to the exact resources, operations, API groups, and scopes that the webhook truly needs.",
	}}
}

func sensitiveWebhookControlIssues(eval webhookEvaluation) []Issue {
	if !webhookTouchesSensitiveAdminResources(eval.rules) {
		return nil
	}
	if webhookHasExplicitControls(eval) {
		return nil
	}
	return []Issue{{
		Kind:           eval.kind,
		Name:           eval.cfgName,
		Severity:       SeverityCritical,
		Category:       "security",
		Check:          "webhook-sensitive-resources-unscoped",
		Summary:        fmt.Sprintf("webhook %s affects secrets, serviceaccounts, or RBAC resources without explicit scoping controls", eval.webhookName),
		Recommendation: "Add namespaceSelector, objectSelector, and/or matchConditions so admission logic that touches credentials or RBAC resources is deliberately scoped and auditable.",
	}}
}

func mutatingSecurityContextIssues(eval webhookEvaluation) []Issue {
	if !strings.Contains(eval.kind, "Mutating") {
		return nil
	}
	if !webhookTouchesPodResources(eval.rules) {
		return nil
	}
	if !webhookLooksLikeSecurityContextMutator(eval) {
		return nil
	}
	severity := SeverityWarning
	if !webhookHasExplicitControls(eval) {
		severity = SeverityCritical
	}
	return []Issue{{
		Kind:           eval.kind,
		Name:           eval.cfgName,
		Severity:       severity,
		Category:       "security",
		Check:          "webhook-mutates-security-context",
		Summary:        fmt.Sprintf("mutating webhook %s may broadly change pod security context or injected containers", eval.webhookName),
		Recommendation: "Document expected mutations, scope them with selectors, and audit patch behavior so security-context changes are intentional rather than surprising side effects.",
	}}
}

func webhookNeedsEnforcement(eval webhookEvaluation) bool {
	if strings.Contains(eval.kind, "Mutating") {
		return false
	}
	if webhookTouchesSensitiveAdminResources(eval.rules) || webhookTouchesSecurityResources(eval.rules) {
		return true
	}
	text := strings.ToLower(webhookDescriptor(eval))
	for _, marker := range []string{"policy", "security", "psa", "psp", "rbac", "secret", "identity", "imageverify", "gatekeeper", "kyverno"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func webhookHasHighDoSRisk(eval webhookEvaluation, readyEndpoints bool) bool {
	if readyEndpoints && eval.timeoutSeconds <= 10 && webhookHasExplicitControls(eval) && !webhookRulesClusterWide(eval.rules) {
		return false
	}
	if webhookNeedsEnforcement(eval) && readyEndpoints && eval.timeoutSeconds <= 10 {
		return false
	}
	return webhookRulesClusterWide(eval.rules) || !readyEndpoints || eval.timeoutSeconds > 10 || !webhookHasExplicitControls(eval)
}

func webhookHasExplicitControls(eval webhookEvaluation) bool {
	return labelSelectorHasRequirements(eval.namespaceSelector) || labelSelectorHasRequirements(eval.objectSelector) || len(eval.matchConditions) > 0
}

func labelSelectorHasRequirements(selector *metav1.LabelSelector) bool {
	if selector == nil {
		return false
	}
	return len(selector.MatchLabels) > 0 || len(selector.MatchExpressions) > 0
}

func webhookRulesClusterWide(rules []admissionv1.RuleWithOperations) bool {
	for _, rule := range rules {
		if containsOperation(rule.Operations, admissionv1.OperationAll) || hasWildcard(rule.Rule.APIGroups) || hasWildcard(rule.Rule.Resources) || rule.Rule.Scope == nil {
			return true
		}
	}
	return false
}

func webhookTouchesSensitiveAdminResources(rules []admissionv1.RuleWithOperations) bool {
	return webhookTouchesResource(rules, []string{"secrets", "serviceaccounts", "roles", "rolebindings", "clusterroles", "clusterrolebindings"})
}

func webhookTouchesSecurityResources(rules []admissionv1.RuleWithOperations) bool {
	return webhookTouchesResource(rules, []string{"pods", "pods/ephemeralcontainers", "namespaces", "networkpolicies", "podsecuritypolicies"})
}

func webhookTouchesPodResources(rules []admissionv1.RuleWithOperations) bool {
	return webhookTouchesResource(rules, []string{"pods", "pods/ephemeralcontainers"}) && (containsOperationInRules(rules, admissionv1.Create) || containsOperationInRules(rules, admissionv1.Update) || containsOperationInRules(rules, admissionv1.OperationAll))
}

func webhookTouchesResource(rules []admissionv1.RuleWithOperations, resources []string) bool {
	for _, rule := range rules {
		if hasWildcard(rule.Rule.Resources) {
			return true
		}
		for _, resource := range rule.Rule.Resources {
			base := strings.Split(resource, "/")[0]
			for _, expected := range resources {
				if resource == expected || base == expected {
					return true
				}
			}
		}
	}
	return false
}

func containsOperationInRules(rules []admissionv1.RuleWithOperations, operation admissionv1.OperationType) bool {
	for _, rule := range rules {
		if containsOperation(rule.Operations, operation) {
			return true
		}
	}
	return false
}

func containsOperation(operations []admissionv1.OperationType, expected admissionv1.OperationType) bool {
	if len(operations) == 0 {
		return false
	}
	for _, operation := range operations {
		if operation == expected {
			return true
		}
	}
	return false
}

func webhookLooksLikeSecurityContextMutator(eval webhookEvaluation) bool {
	text := strings.ToLower(webhookDescriptor(eval))
	for _, marker := range []string{"inject", "sidecar", "proxy", "mesh", "security", "seccomp", "apparmor", "capabil", "privileg", "vault", "agent", "init"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return !webhookHasExplicitControls(eval)
}

func webhookDescriptor(eval webhookEvaluation) string {
	serviceName := ""
	servicePath := ""
	if eval.clientConfig.Service != nil {
		serviceName = eval.clientConfig.Service.Name
		servicePath = pointerString(eval.clientConfig.Service.Path)
	}
	return strings.Join([]string{eval.cfgName, eval.webhookName, serviceName, servicePath}, " ")
}

func serviceSelectedPods(service corev1.Service, pods []corev1.Pod) []corev1.Pod {
	if len(service.Spec.Selector) == 0 {
		return nil
	}
	selector := labels.SelectorFromSet(labels.Set(service.Spec.Selector))
	matched := make([]corev1.Pod, 0)
	for _, pod := range pods {
		if selector.Matches(labels.Set(pod.Labels)) {
			matched = append(matched, pod)
		}
	}
	return matched
}

func podReferencedSecrets(pod corev1.Pod) []string {
	names := make([]string, 0)
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.SecretName != "" {
			names = append(names, volume.Secret.SecretName)
		}
		if volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			if source.Secret != nil && source.Secret.Name != "" {
				names = append(names, source.Secret.Name)
			}
		}
	}
	return uniqueStrings(names)
}

func webhookServiceDNSNames(service corev1.Service) []string {
	return []string{
		service.Name,
		service.Name + "." + service.Namespace,
		service.Name + "." + service.Namespace + ".svc",
		service.Name + "." + service.Namespace + ".svc.cluster.local",
	}
}

func secretLooksLikeWebhookCertificate(secret corev1.Secret, serviceNames []string) bool {
	name := strings.ToLower(secret.Name)
	if strings.Contains(name, "webhook") || strings.Contains(name, "tls") || strings.Contains(name, "cert") {
		return true
	}
	for _, cert := range parsePEMCertificates(secret.Data["tls.crt"]) {
		if cert == nil {
			continue
		}
		if certificateMatchesAnyDNSName(cert, serviceNames) {
			return true
		}
	}
	return false
}

func certificateMatchesAnyDNSName(cert *x509.Certificate, names []string) bool {
	if cert == nil {
		return false
	}
	for _, name := range names {
		if strings.EqualFold(cert.Subject.CommonName, name) {
			return true
		}
		for _, dnsName := range cert.DNSNames {
			if strings.EqualFold(dnsName, name) {
				return true
			}
		}
	}
	return false
}

// probeWebhookLatency issues lightweight GET and AdmissionReview POST probes via the service proxy.
func probeWebhookLatency(ctx context.Context, cs *kubernetes.Clientset, ns, svc string) []Issue {
	var issues []Issue

	start := time.Now()
	res := cs.CoreV1().RESTClient().Get().Namespace(ns).Resource("services").Name(svc).SubResource("proxy").Do(ctx)
	if _, err := res.Raw(); err != nil {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-probe",
			Summary:        fmt.Sprintf("webhook service %s/%s probe failed: %v", ns, svc, err),
			Recommendation: "Check webhook pod readiness, network policy, and service endpoints.",
		})
	}
	latency := time.Since(start)
	if latency > 1500*time.Millisecond {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-latency",
			Summary:        fmt.Sprintf("webhook service %s/%s slow (~%dms)", ns, svc, latency.Milliseconds()),
			Recommendation: "Investigate webhook handler performance and network path; consider lowering timeoutSeconds.",
		})
	}

	// AdmissionReview POST probe (best-effort).
	admissionPayload := []byte(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","request":{"uid":"00000000-0000-0000-0000-000000000000","kind":{"group":"","version":"v1","kind":"Pod"},"resource":{"group":"","version":"v1","resource":"pods"},"operation":"CONNECT","object":{},"name":"","namespace":""}}`)
	postStart := time.Now()
	postReq := cs.CoreV1().RESTClient().Post().Namespace(ns).Resource("services").Name(svc).SubResource("proxy").Body(bytes.NewReader(admissionPayload)).SetHeader("Content-Type", "application/json")
	resp := postReq.Do(ctx)
	_, err := resp.Raw()
	postLatency := time.Since(postStart)
	if err != nil {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-admission-probe",
			Summary:        fmt.Sprintf("admission probe to %s/%s failed: %v", ns, svc, err),
			Recommendation: "Ensure webhook endpoint accepts admission reviews; verify TLS, service port, and readiness.",
		})
	} else if postLatency > 1500*time.Millisecond {
		issues = append(issues, Issue{
			Kind:           "Webhook",
			Namespace:      ns,
			Name:           svc,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "webhook-admission-latency",
			Summary:        fmt.Sprintf("admission probe to %s/%s slow (~%dms)", ns, svc, postLatency.Milliseconds()),
			Recommendation: "Investigate webhook handler performance and network latency; consider lower timeoutSeconds.",
		})
	}

	return issues
}

func hasReadyAddress(eps *corev1.Endpoints) bool {
	for _, subset := range eps.Subsets {
		if len(subset.Addresses) > 0 {
			return true
		}
	}
	return false
}
