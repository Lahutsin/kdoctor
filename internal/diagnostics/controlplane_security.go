package diagnostics

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckControlPlaneSecurity(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}

	var issues []Issue

	components, err := discoverControlPlaneComponents(ctx, cs)
	if err != nil {
		return nil, err
	}

	if pod := firstComponentPod(components["kube-apiserver"]); pod != nil {
		issues = append(issues, inspectAPIServerSecurity(*pod)...)
	}
	if pod := firstComponentPod(components["etcd"]); pod != nil {
		issues = append(issues, inspectEtcdSecurity(*pod)...)
	}
	if pod := firstComponentPod(components["kube-scheduler"]); pod != nil {
		issues = append(issues, inspectSchedulerSecurity(*pod)...)
	}
	if pod := firstComponentPod(components["kube-controller-manager"]); pod != nil {
		issues = append(issues, inspectControllerManagerSecurity(*pod)...)
	}

	issues = append(issues, inspectControlPlaneCertificates(ctx, cs)...)
	issues = append(issues, inspectCertificateRotation(ctx, cs)...)
	issues = append(issues, inspectDeprecatedAPIs(ctx, cs)...)

	return issues, nil
}

func discoverControlPlaneComponents(ctx context.Context, cs *kubernetes.Clientset) (map[string][]corev1.Pod, error) {
	pods, err := cs.CoreV1().Pods(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	components := map[string][]corev1.Pod{
		"kube-apiserver":          {},
		"etcd":                    {},
		"kube-scheduler":          {},
		"kube-controller-manager": {},
	}
	for _, pod := range pods.Items {
		name := strings.ToLower(pod.Name)
		component := pod.Labels["component"]
		switch {
		case component == "kube-apiserver" || strings.Contains(name, "kube-apiserver"):
			components["kube-apiserver"] = append(components["kube-apiserver"], pod)
		case component == "etcd" || strings.Contains(name, "etcd"):
			components["etcd"] = append(components["etcd"], pod)
		case component == "kube-scheduler" || strings.Contains(name, "kube-scheduler"):
			components["kube-scheduler"] = append(components["kube-scheduler"], pod)
		case component == "kube-controller-manager" || strings.Contains(name, "kube-controller-manager"):
			components["kube-controller-manager"] = append(components["kube-controller-manager"], pod)
		}
	}
	return components, nil
}

func firstComponentPod(pods []corev1.Pod) *corev1.Pod {
	if len(pods) == 0 {
		return nil
	}
	return &pods[0]
}

func inspectAPIServerSecurity(pod corev1.Pod) []Issue {
	flags := collectContainerFlags(pod)
	issues := make([]Issue, 0)

	if !isFlagFalse(flags, "anonymous-auth") {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-anonymous-auth", SeverityCritical, "apiserver anonymous auth appears enabled", "Set --anonymous-auth=false on kube-apiserver."))
	}

	authMode := strings.ToUpper(firstFlagValue(flags, "authorization-mode"))
	if authMode == "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-authorization-mode", SeverityWarning, "authorization-mode flag not found", "Ensure kube-apiserver explicitly enables RBAC and avoids weak fallback authz modes."))
	} else {
		if !strings.Contains(authMode, "RBAC") {
			issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-rbac", SeverityCritical, fmt.Sprintf("authorization-mode does not include RBAC (%s)", authMode), "Enable RBAC in --authorization-mode for kube-apiserver."))
		}
		if strings.Contains(authMode, "ALWAYSALLOW") || strings.Contains(authMode, "ABAC") {
			issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-weak-authz", SeverityCritical, fmt.Sprintf("weak authorization mode configured (%s)", authMode), "Remove AlwaysAllow/ABAC fallback and keep RBAC/Node authorization modes."))
		}
	}

	if firstFlagValue(flags, "client-ca-file") == "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-client-ca", SeverityWarning, "client-ca-file flag not found", "Configure --client-ca-file so client certificate authentication is anchored to a trusted CA."))
	}
	if firstFlagValue(flags, "tls-cert-file") == "" || firstFlagValue(flags, "tls-private-key-file") == "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-tls-serving", SeverityCritical, "apiserver serving certificate flags are incomplete", "Ensure --tls-cert-file and --tls-private-key-file are configured for secure serving."))
	}
	if insecurePortEnabled(flags, "insecure-port") {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-insecure-port", SeverityCritical, "apiserver insecure port is enabled", "Disable --insecure-port and rely on authenticated TLS endpoints only."))
	}
	if firstFlagValue(flags, "basic-auth-file") != "" || firstFlagValue(flags, "token-auth-file") != "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-legacy-auth", SeverityCritical, "legacy basic or static token authentication is configured", "Remove --basic-auth-file/--token-auth-file and use modern identity providers with RBAC."))
	}
	if firstFlagValue(flags, "encryption-provider-config") == "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-secret-encryption", SeverityWarning, "secret encryption at rest is not explicitly configured", "Set --encryption-provider-config to encrypt secrets stored in etcd."))
	}

	enabledPlugins := splitCSVFlag(flags, "enable-admission-plugins")
	disabledPlugins := splitCSVFlag(flags, "disable-admission-plugins")
	for _, plugin := range []string{"NamespaceLifecycle", "ServiceAccount", "ResourceQuota", "ValidatingAdmissionWebhook", "MutatingAdmissionWebhook"} {
		if containsFold(disabledPlugins, plugin) {
			issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-admission-disabled", SeverityCritical, fmt.Sprintf("required admission plugin %s is disabled", plugin), "Remove the plugin from --disable-admission-plugins."))
		}
		if len(enabledPlugins) > 0 && !containsFold(enabledPlugins, plugin) {
			issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-admission-missing", SeverityWarning, fmt.Sprintf("required admission plugin %s is missing from enable-admission-plugins", plugin), "Include the plugin in --enable-admission-plugins when explicitly managing the admission chain."))
		}
	}
	if containsFold(disabledPlugins, "PodSecurity") {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-podsecurity-disabled", SeverityWarning, "PodSecurity admission plugin is disabled", "Enable PodSecurity admission or enforce equivalent policy controls."))
	}

	auditPath := firstFlagValue(flags, "audit-log-path")
	auditPolicy := firstFlagValue(flags, "audit-policy-file")
	if auditPath == "" || auditPolicy == "" {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-audit-logging", SeverityWarning, "audit logging flags are incomplete", "Configure --audit-log-path and --audit-policy-file for meaningful audit coverage."))
	}
	if maxAge := firstFlagInt(flags, "audit-log-maxage"); maxAge > 0 && maxAge < 7 {
		issues = append(issues, controlPlaneSecurityIssue("APIServer", pod.Name, "apiserver-audit-retention", SeverityInfo, fmt.Sprintf("audit log retention maxage is short (%d days)", maxAge), "Increase audit log retention if incident response needs longer history."))
	}

	return issues
}

func inspectEtcdSecurity(pod corev1.Pod) []Issue {
	flags := collectContainerFlags(pod)
	issues := make([]Issue, 0)

	for _, key := range []string{"cert-file", "key-file", "trusted-ca-file", "peer-cert-file", "peer-key-file", "peer-trusted-ca-file"} {
		if firstFlagValue(flags, key) == "" {
			issues = append(issues, controlPlaneSecurityIssue("etcd", pod.Name, "etcd-tls-config", SeverityCritical, fmt.Sprintf("etcd flag --%s is not configured", key), "Configure etcd for mutual TLS on both client and peer traffic."))
		}
	}
	if !isFlagTrue(flags, "client-cert-auth") || !isFlagTrue(flags, "peer-client-cert-auth") {
		issues = append(issues, controlPlaneSecurityIssue("etcd", pod.Name, "etcd-client-cert-auth", SeverityCritical, "etcd client or peer certificate authentication appears disabled", "Enable --client-cert-auth=true and --peer-client-cert-auth=true."))
	}
	for _, key := range []string{"listen-client-urls", "listen-peer-urls", "advertise-client-urls", "initial-advertise-peer-urls"} {
		if value := strings.ToLower(firstFlagValue(flags, key)); strings.Contains(value, "http://") {
			issues = append(issues, controlPlaneSecurityIssue("etcd", pod.Name, "etcd-insecure-urls", SeverityCritical, fmt.Sprintf("etcd flag --%s contains insecure http URLs", key), "Use https URLs only for etcd client and peer endpoints."))
		}
	}
	if firstFlagValue(flags, "listen-client-http-urls") != "" {
		issues = append(issues, controlPlaneSecurityIssue("etcd", pod.Name, "etcd-insecure-http", SeverityCritical, "etcd listen-client-http-urls is configured", "Remove insecure client HTTP listeners from etcd."))
	}

	return issues
}

func inspectSchedulerSecurity(pod corev1.Pod) []Issue {
	flags := collectContainerFlags(pod)
	issues := make([]Issue, 0)
	if insecurePortEnabled(flags, "port") {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "scheduler-insecure-port", SeverityCritical, "scheduler insecure port is enabled", "Disable the scheduler insecure port and use authenticated secure serving only."))
	}
	if firstFlagValue(flags, "authentication-kubeconfig") == "" || firstFlagValue(flags, "authorization-kubeconfig") == "" {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "scheduler-authn-authz", SeverityWarning, "scheduler authn/authz kubeconfigs are not explicit", "Configure scheduler authentication-kubeconfig and authorization-kubeconfig."))
	}
	return issues
}

func inspectControllerManagerSecurity(pod corev1.Pod) []Issue {
	flags := collectContainerFlags(pod)
	issues := make([]Issue, 0)
	if insecurePortEnabled(flags, "port") {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "controller-manager-insecure-port", SeverityCritical, "controller-manager insecure port is enabled", "Disable the controller-manager insecure port and use authenticated secure serving only."))
	}
	if firstFlagValue(flags, "authentication-kubeconfig") == "" || firstFlagValue(flags, "authorization-kubeconfig") == "" {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "controller-manager-authn-authz", SeverityWarning, "controller-manager authn/authz kubeconfigs are not explicit", "Configure controller-manager authentication-kubeconfig and authorization-kubeconfig."))
	}
	if firstFlagValue(flags, "cluster-signing-cert-file") == "" || firstFlagValue(flags, "cluster-signing-key-file") == "" {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "controller-manager-cluster-signing", SeverityWarning, "controller-manager cluster signing files are not explicit", "Configure cluster-signing cert/key files to support controlled certificate issuance and rotation."))
	}
	if duration := firstFlagDuration(flags, "cluster-signing-duration"); duration > 365*24*time.Hour {
		issues = append(issues, controlPlaneSecurityIssue("ControlPlane", pod.Name, "controller-manager-signing-duration", SeverityInfo, fmt.Sprintf("cluster-signing-duration is long (%s)", duration), "Consider shortening certificate lifetimes if your rotation processes can support it."))
	}
	return issues
}

func inspectControlPlaneCertificates(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	secrets, err := cs.CoreV1().Secrets(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	issues := make([]Issue, 0)
	for _, secret := range secrets.Items {
		nameLower := strings.ToLower(secret.Name)
		if !strings.Contains(nameLower, "apiserver") && !strings.Contains(nameLower, "etcd") && !strings.Contains(nameLower, "scheduler") && !strings.Contains(nameLower, "controller-manager") && !strings.Contains(nameLower, "front-proxy") && !strings.Contains(nameLower, "kubelet") {
			continue
		}
		if crt := secret.Data["tls.crt"]; len(crt) > 0 {
			issues = append(issues, evaluateCertificateBundle(secret.Namespace, secret.Name, "Certificate", crt, "controlplane-cert-expiry")...)
			if ca := secret.Data["ca.crt"]; len(ca) > 0 {
				issues = append(issues, verifyCertificateChain(secret.Namespace, secret.Name, crt, ca)...)
			}
		}
		if crt := secret.Data["apiserver.crt"]; len(crt) > 0 {
			issues = append(issues, evaluateCertificateBundle(secret.Namespace, secret.Name, "Certificate", crt, "controlplane-cert-expiry")...)
		}
	}
	return issues
}

func verifyCertificateChain(namespace, name string, certPEM, caPEM []byte) []Issue {
	certs := parsePEMCertificates(certPEM)
	cas := parsePEMCertificates(caPEM)
	if len(certs) == 0 || len(cas) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, cert := range cas {
		pool.AddCert(cert)
	}
	issues := make([]Issue, 0)
	for _, cert := range certs {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now()}); err != nil {
			issues = append(issues, Issue{
				Kind:           "Certificate",
				Namespace:      namespace,
				Name:           name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "controlplane-cert-chain",
				Summary:        fmt.Sprintf("control-plane certificate chain verification failed for CN=%s: %v", cert.Subject.CommonName, err),
				Recommendation: "Verify the certificate issuer, CA bundle, and renewal chain for control-plane certificates.",
			})
		}
	}
	return issues
}

func inspectCertificateRotation(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	csrs, err := cs.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	issues := make([]Issue, 0)
	var recentApproved bool
	for _, csr := range csrs.Items {
		signer := string(csr.Spec.SignerName)
		if !strings.Contains(signer, "kubelet") && !strings.Contains(signer, "kube-apiserver-client-kubelet") {
			continue
		}
		if csrApproved(&csr) {
			when := csrApprovalTime(&csr)
			if !when.IsZero() && time.Since(when) <= 30*24*time.Hour {
				recentApproved = true
			}
			continue
		}
		age := time.Since(csr.CreationTimestamp.Time)
		if age > 24*time.Hour {
			issues = append(issues, Issue{
				Kind:           "ControlPlane",
				Name:           csr.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "certificate-rotation-pending-csr",
				Summary:        fmt.Sprintf("certificate signing request %s has been pending for %s", csr.Name, humanDuration(age)),
				Recommendation: "Inspect kubelet/controller-manager certificate rotation flow and approve or fix stuck CSRs.",
			})
		}
	}
	if !recentApproved {
		issues = append(issues, Issue{
			Kind:           "ControlPlane",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "certificate-rotation-observed",
			Summary:        "no recent kubelet certificate rotations observed in CSR history",
			Recommendation: "Confirm kubelet/control-plane certificate rotation is enabled and CSR approval flow is healthy.",
		})
	}
	return issues
}

func inspectDeprecatedAPIs(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	res := cs.Discovery().RESTClient().Get().AbsPath("/metrics").Do(ctx)
	raw, err := res.Raw()
	if err != nil {
		return nil
	}
	issues := make([]Issue, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "apiserver_requested_deprecated_apis") {
			continue
		}
		value, ok := parsePromGauge(line)
		if !ok || value <= 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "APIServer",
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "deprecated-apis",
			Summary:        fmt.Sprintf("deprecated API usage observed: %s", line),
			Recommendation: "Migrate workloads and clients away from deprecated APIs before the target removal release.",
		})
		if len(issues) >= 5 {
			break
		}
	}
	return issues
}

func collectContainerFlags(pod corev1.Pod) map[string][]string {
	flags := map[string][]string{}
	if len(pod.Spec.Containers) == 0 {
		return flags
	}
	container := pod.Spec.Containers[0]
	tokens := append([]string{}, container.Command...)
	tokens = append(tokens, container.Args...)
	for i := 0; i < len(tokens); i++ {
		token := strings.TrimSpace(tokens[i])
		if !strings.HasPrefix(token, "--") {
			continue
		}
		key := strings.TrimPrefix(token, "--")
		value := "true"
		if idx := strings.Index(key, "="); idx != -1 {
			value = key[idx+1:]
			key = key[:idx]
		} else if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "--") {
			value = tokens[i+1]
			i++
		}
		flags[key] = append(flags[key], value)
	}
	return flags
}

func firstFlagValue(flags map[string][]string, key string) string {
	values := flags[key]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func splitCSVFlag(flags map[string][]string, key string) []string {
	value := firstFlagValue(flags, key)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstFlagInt(flags map[string][]string, key string) int {
	value := firstFlagValue(flags, key)
	if value == "" {
		return 0
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return v
}

func firstFlagDuration(flags map[string][]string, key string) time.Duration {
	value := firstFlagValue(flags, key)
	if value == "" {
		return 0
	}
	d, err := time.ParseDuration(value)
	if err == nil {
		return d
	}
	if strings.HasSuffix(value, "d") {
		days, convErr := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if convErr == nil {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	return 0
}

func isFlagFalse(flags map[string][]string, key string) bool {
	value := strings.ToLower(firstFlagValue(flags, key))
	return value == "false" || value == "0"
}

func isFlagTrue(flags map[string][]string, key string) bool {
	value := strings.ToLower(firstFlagValue(flags, key))
	return value == "true" || value == "1"
}

func insecurePortEnabled(flags map[string][]string, key string) bool {
	value := firstFlagValue(flags, key)
	if value == "" {
		return false
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		return false
	}
	return v > 0
}

func containsFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func controlPlaneSecurityIssue(kind, name, check string, sev Severity, summary, rec string) Issue {
	return Issue{
		Kind:           kind,
		Namespace:      metav1.NamespaceSystem,
		Name:           name,
		Severity:       sev,
		Category:       "security",
		Check:          check,
		Summary:        summary,
		Recommendation: rec,
	}
}

func csrApproved(csr *certificatesv1.CertificateSigningRequest) bool {
	if csr == nil {
		return false
	}
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func csrApprovalTime(csr *certificatesv1.CertificateSigningRequest) time.Time {
	if csr == nil {
		return time.Time{}
	}
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved && condition.LastUpdateTime.Time.After(time.Time{}) {
			return condition.LastUpdateTime.Time
		}
	}
	return time.Time{}
}
