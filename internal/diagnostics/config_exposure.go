package diagnostics

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckConfigAndDataExposure(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	configMaps, err := cs.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
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
	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		ingresses = &networkingv1.IngressList{}
	}
	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	issues = append(issues, inspectConfigMapsForSecrets(configMaps.Items)...)
	issues = append(issues, envSensitiveValueIssues(pods.Items)...)
	issues = append(issues, secretLoggingRiskIssues(pods.Items)...)
	issues = append(issues, publicAdminUIIssues(services.Items, ingresses.Items)...)
	issues = append(issues, publicDebugEndpointIssues(services.Items, ingresses.Items)...)
	issues = append(issues, metadataExposureIssues(pods.Items, services.Items, ingresses.Items, namespaces)...)

	return dedupeIssues(issues), nil
}

func envSensitiveValueIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			findings := make([]string, 0)
			for _, env := range container.Env {
				if !looksSensitiveConfigKey(env.Name) {
					continue
				}
				if env.ValueFrom != nil {
					findings = append(findings, env.Name+":valueFrom")
					continue
				}
				if strings.TrimSpace(env.Value) == "" {
					continue
				}
				findings = append(findings, env.Name+":literal")
			}
			if len(findings) == 0 {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "env-sensitive-values",
				Summary:        fmt.Sprintf("container %s exposes sensitive env vars: %s", container.Name, strings.Join(uniqueStrings(findings), ", ")),
				Recommendation: "Avoid putting secrets in environment variables where possible; prefer secret volume mounts or workload identity, and avoid literal sensitive values in pod specs.",
			})
		}
	}
	return issues
}

func secretLoggingRiskIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		debugEnabled := false
		hasSensitiveEnv := false
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			if containerLikelyLogsVerbosely(container) {
				debugEnabled = true
			}
			for _, env := range container.Env {
				if !looksSensitiveConfigKey(env.Name) {
					continue
				}
				hasSensitiveEnv = true
				break
			}
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil || envFrom.ConfigMapRef != nil {
					hasSensitiveEnv = true
					break
				}
			}
		}
		if !debugEnabled || !hasSensitiveEnv {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "logging-secret-risk",
			Summary:        "workload combines verbose/debug logging settings with sensitive environment-sourced configuration",
			Recommendation: "Lower log verbosity in production and review application logging so secrets, tokens, and full request payloads are never emitted to logs.",
		})
	}
	return issues
}

func publicAdminUIIssues(services []corev1.Service, ingresses []networkingv1.Ingress) []Issue {
	issues := make([]Issue, 0)
	publicServices := map[string]corev1.Service{}
	for _, service := range services {
		if !serviceExternallyReachable(service) || !looksLikeAdminUI(service.Name, service.Labels) {
			continue
		}
		publicServices[service.Namespace+"/"+service.Name] = service
		issues = append(issues, Issue{
			Kind:           "Service",
			Namespace:      service.Namespace,
			Name:           service.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "public-admin-ui",
			Summary:        fmt.Sprintf("service exposing admin or dashboard UI is externally reachable (%s)", service.Spec.Type),
			Recommendation: "Restrict dashboard and admin UIs behind authentication, network policy, VPN, or private ingress rather than exposing them broadly.",
		})
	}
	for _, ingress := range ingresses {
		if !ingressLooksPublic(ingress) {
			continue
		}
		if !ingressAuthConfigured(ingress) && ingressTargetsAdminUI(ingress, publicServices) {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ingress.Namespace,
				Name:           ingress.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "public-admin-ui",
				Summary:        "ingress exposes an admin or dashboard UI without obvious auth annotations",
				Recommendation: "Require auth on ingress for dashboards and admin UIs, or keep them on private/internal ingress paths only.",
			})
		}
	}
	return issues
}

func publicDebugEndpointIssues(services []corev1.Service, ingresses []networkingv1.Ingress) []Issue {
	issues := make([]Issue, 0)
	debugServices := map[string]corev1.Service{}
	for _, service := range services {
		ports := serviceDebugPorts(service)
		if len(ports) == 0 {
			continue
		}
		debugServices[service.Namespace+"/"+service.Name] = service
		if serviceExternallyReachable(service) {
			issues = append(issues, Issue{
				Kind:           "Service",
				Namespace:      service.Namespace,
				Name:           service.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "public-debug-endpoint",
				Summary:        fmt.Sprintf("service exposes debug, metrics, or profiling ports externally: %s", strings.Join(ports, ", ")),
				Recommendation: "Do not publish metrics, pprof, or debug ports directly; expose them only on internal networks or behind strong authentication.",
			})
		}
	}
	for _, ingress := range ingresses {
		if !ingressLooksPublic(ingress) || ingressAuthConfigured(ingress) {
			continue
		}
		if !ingressTargetsDebugService(ingress, debugServices) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ingress.Namespace,
			Name:           ingress.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "public-debug-endpoint",
			Summary:        "ingress appears to expose metrics, debug, or pprof endpoints without obvious auth",
			Recommendation: "Keep debug and profiling endpoints private, or add ingress auth and network restrictions before exposing them.",
		})
	}
	return issues
}

func metadataExposureIssues(pods []corev1.Pod, services []corev1.Service, ingresses []networkingv1.Ingress, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, ns := range namespaces {
		issues = append(issues, sensitiveMetadataMapIssues("Namespace", ns.name, ns.name, ns.annotations, "annotations")...)
		issues = append(issues, sensitiveMetadataMapIssues("Namespace", ns.name, ns.name, ns.labels, "labels")...)
	}
	for _, pod := range pods {
		issues = append(issues, sensitiveMetadataMapIssues("Pod", pod.Namespace, pod.Name, pod.Annotations, "annotations")...)
		issues = append(issues, sensitiveMetadataMapIssues("Pod", pod.Namespace, pod.Name, pod.Labels, "labels")...)
	}
	for _, service := range services {
		issues = append(issues, sensitiveMetadataMapIssues("Service", service.Namespace, service.Name, service.Annotations, "annotations")...)
		issues = append(issues, sensitiveMetadataMapIssues("Service", service.Namespace, service.Name, service.Labels, "labels")...)
	}
	for _, ingress := range ingresses {
		issues = append(issues, sensitiveMetadataMapIssues("Ingress", ingress.Namespace, ingress.Name, ingress.Annotations, "annotations")...)
		issues = append(issues, sensitiveMetadataMapIssues("Ingress", ingress.Namespace, ingress.Name, ingress.Labels, "labels")...)
	}
	return issues
}

func inspectConfigMapsForSecrets(configMaps []corev1.ConfigMap) []Issue {
	issues := make([]Issue, 0)
	for _, configMap := range configMaps {
		findings := make([]string, 0)
		for key, value := range configMap.Data {
			if looksSensitiveConfigKey(key) || looksSensitiveConfigValue(value) || looksStructuredCredential(value) {
				findings = append(findings, key)
			}
		}
		if len(findings) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "ConfigMap",
			Namespace:      configMap.Namespace,
			Name:           configMap.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "configmap-secret-leak",
			Summary:        fmt.Sprintf("configmap appears to contain secrets or credentials in keys: %s", strings.Join(uniqueStrings(findings), ", ")),
			Recommendation: "Move credentials and private key material out of ConfigMaps into Secrets or an external secret manager, then rotate exposed values.",
		})
	}
	return issues
}

func sensitiveMetadataMapIssues(kind, namespace, name string, values map[string]string, area string) []Issue {
	if len(values) == 0 {
		return nil
	}
	findings := make([]string, 0)
	for key, value := range values {
		if looksSensitiveConfigKey(key) || looksSensitiveConfigValue(value) || len(value) > 256 && looksStructuredCredential(value) {
			findings = append(findings, key)
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return []Issue{{
		Kind:           kind,
		Namespace:      namespace,
		Name:           name,
		Severity:       SeverityWarning,
		Category:       "security",
		Check:          "metadata-sensitive-exposure",
		Summary:        fmt.Sprintf("%s contains sensitive-looking %s: %s", strings.ToLower(kind), area, strings.Join(uniqueStrings(findings), ", ")),
		Recommendation: "Do not place tokens, passwords, private keys, or large credential blobs in labels or annotations because they are widely replicated and easy to enumerate.",
	}}
}

func containerLikelyLogsVerbosely(container corev1.Container) bool {
	fields := append([]string{container.Name, container.Image}, container.Command...)
	fields = append(fields, container.Args...)
	for _, env := range container.Env {
		fields = append(fields, env.Name+"="+env.Value)
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"log-level=debug", "log_level=debug", "--debug", "debug=true", "trace", "v=6", "v=7", "v=8", "v=9", "zap-log-level=debug"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func looksLikeAdminUI(name string, labels map[string]string) bool {
	fields := []string{name}
	for key, value := range labels {
		fields = append(fields, key, value)
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"dashboard", "grafana", "kibana", "argocd", "argo-cd", "jenkins", "prometheus", "alertmanager", "admin", "console", "ui"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func serviceExternallyReachable(service corev1.Service) bool {
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer || service.Spec.Type == corev1.ServiceTypeNodePort {
		return true
	}
	return len(service.Spec.ExternalIPs) > 0
}

func ingressLooksPublic(ingress networkingv1.Ingress) bool {
	if len(ingress.Spec.Rules) == 0 && len(ingress.Spec.TLS) == 0 {
		return false
	}
	if class := strings.ToLower(pointerString(ingress.Spec.IngressClassName)); strings.Contains(class, "internal") || strings.Contains(class, "private") {
		return false
	}
	for key, value := range ingress.Annotations {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)
		if strings.Contains(keyLower, "scheme") && strings.Contains(valueLower, "internal") {
			return false
		}
		if strings.Contains(keyLower, "ingress.kubernetes.io/whitelist-source-range") || strings.Contains(keyLower, "nginx.ingress.kubernetes.io/whitelist-source-range") {
			return false
		}
	}
	return true
}

func ingressAuthConfigured(ingress networkingv1.Ingress) bool {
	for key, value := range ingress.Annotations {
		combined := strings.ToLower(key + "=" + value)
		for _, marker := range []string{"auth-url", "auth-type", "auth-signin", "oauth", "oidc", "basic-auth", "external-auth", "forward-auth", "jwt"} {
			if strings.Contains(combined, marker) {
				return true
			}
		}
	}
	return false
}

func ingressTargetsAdminUI(ingress networkingv1.Ingress, services map[string]corev1.Service) bool {
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			service, ok := services[ingress.Namespace+"/"+path.Backend.Service.Name]
			if ok && looksLikeAdminUI(service.Name, service.Labels) {
				return true
			}
			pathText := strings.ToLower(rule.Host + path.Path + path.Backend.Service.Name)
			for _, marker := range []string{"dashboard", "grafana", "admin", "argocd", "jenkins", "prometheus", "kibana"} {
				if strings.Contains(pathText, marker) {
					return true
				}
			}
		}
	}
	return false
}

func serviceDebugPorts(service corev1.Service) []string {
	ports := make([]string, 0)
	for _, port := range service.Spec.Ports {
		name := strings.ToLower(port.Name)
		for _, marker := range []string{"metrics", "pprof", "debug", "admin", "actuator", "profiling"} {
			if strings.Contains(name, marker) {
				ports = append(ports, fmt.Sprintf("%s:%d", port.Name, port.Port))
				break
			}
		}
		if port.Port == 6060 || port.Port == 9090 || port.Port == 9091 {
			ports = append(ports, fmt.Sprintf("%s:%d", port.Name, port.Port))
		}
	}
	return uniqueStrings(ports)
}

func ingressTargetsDebugService(ingress networkingv1.Ingress, services map[string]corev1.Service) bool {
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			service, ok := services[ingress.Namespace+"/"+path.Backend.Service.Name]
			if ok && len(serviceDebugPorts(service)) > 0 {
				return true
			}
			pathText := strings.ToLower(rule.Host + path.Path)
			for _, marker := range []string{"/metrics", "/pprof", "/debug", "/actuator", "/prometheus"} {
				if strings.Contains(pathText, marker) {
					return true
				}
			}
		}
	}
	return false
}

func looksStructuredCredential(value string) bool {
	text := strings.TrimSpace(strings.ToLower(value))
	if strings.Contains(text, "-----begin") {
		return true
	}
	if strings.Count(value, ".") == 2 && len(value) > 40 {
		return true
	}
	if strings.Contains(text, "type\": \"service_account\"") || strings.Contains(text, "clientsecret") {
		return true
	}
	return false
}

func pointerString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
