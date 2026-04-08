package diagnostics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	gatewayGVR   = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	httpRouteGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
)

func CheckIngresses(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var issues []Issue

	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}
	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	serviceIndex := make(map[string]corev1.Service, len(services.Items))
	for _, service := range services.Items {
		serviceIndex[service.Namespace+"/"+service.Name] = service
	}

	issues = append(issues, checkIngressControllers(ctx, cs)...)
	issues = append(issues, loadBalancerInternalExposureIssues(services.Items, namespaces)...)
	issues = append(issues, nodePortSensitiveExposureIssues(services.Items, namespaces)...)

	for _, ing := range ingresses.Items {
		if len(ing.Status.LoadBalancer.Ingress) == 0 {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ing.Namespace,
				Name:           ing.Name,
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "ingress-loadbalancer",
				Summary:        "ingress has no load balancer status",
				Recommendation: "Verify the ingress controller reconciles this resource and that the underlying load balancer provisioned successfully.",
			})
		}

		issues = append(issues, checkIngressBackends(ctx, cs, ing)...)
		issues = append(issues, checkIngressTLS(ctx, cs, ing, namespaces[ing.Namespace])...)
		issues = append(issues, checkIngressExternalExposure(ing, namespaces[ing.Namespace], serviceIndex)...)
		if HostNetworkProbeEnabled("ingress") {
			issues = append(issues, probeIngressHandshake(ing)...)
		}
	}

	issues = append(issues, checkGatewayExposure(ctx, cs, dyn, ns, namespaces)...)

	return dedupeIssues(issues), nil
}

func checkIngressControllers(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	controllers, err := cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	issues := make([]Issue, 0)
	for _, deploy := range controllers.Items {
		name := strings.ToLower(deploy.Name)
		if !strings.Contains(name, "ingress") && !strings.Contains(name, "gateway") && !strings.Contains(name, "traefik") && !strings.Contains(name, "nginx") {
			continue
		}
		desired := int32(1)
		if deploy.Spec.Replicas != nil {
			desired = *deploy.Spec.Replicas
		}
		if deploy.Status.AvailableReplicas < desired {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      deploy.Namespace,
				Name:           deploy.Name,
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "ingress-controller",
				Summary:        fmt.Sprintf("ingress controller deployment not fully available (%d/%d)", deploy.Status.AvailableReplicas, desired),
				Recommendation: "Check controller logs, service account permissions, and node scheduling for the ingress controller.",
			})
		}
	}
	return issues
}

func checkIngressBackends(ctx context.Context, cs *kubernetes.Clientset, ing networkingv1.Ingress) []Issue {
	issues := make([]Issue, 0)
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			svcName := path.Backend.Service.Name
			if _, err := cs.CoreV1().Services(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{}); err != nil {
				issues = append(issues, Issue{
					Kind:           "Ingress",
					Namespace:      ing.Namespace,
					Name:           ing.Name,
					Severity:       SeverityCritical,
					Category:       "networking",
					Check:          "ingress-backend-service",
					Summary:        fmt.Sprintf("backend service %s for host %s is missing", svcName, rule.Host),
					Recommendation: "Restore the service or update ingress backend references.",
				})
				continue
			}
			eps, err := cs.CoreV1().Endpoints(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{})
			if err == nil && !hasReadyAddress(eps) {
				issues = append(issues, Issue{
					Kind:           "Ingress",
					Namespace:      ing.Namespace,
					Name:           ing.Name,
					Severity:       SeverityWarning,
					Category:       "networking",
					Check:          "ingress-backend-endpoints",
					Summary:        fmt.Sprintf("backend service %s has no ready endpoints", svcName),
					Recommendation: "Ensure backend pods are Ready and selected by the service.",
				})
			}
		}
	}
	return issues
}

func checkIngressTLS(ctx context.Context, cs *kubernetes.Clientset, ing networkingv1.Ingress, ns namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	if ingressLooksPublic(ing) && ingressNeedsTLS(ing) {
		severity := SeverityWarning
		if isProductionNamespace(ns) || ingressLooksSensitive(ing) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "ingress-no-tls",
			Summary:        "public ingress routes traffic without TLS",
			Recommendation: "Terminate TLS on every public ingress host and redirect HTTP traffic to HTTPS before exposing it broadly.",
			References:     ingressHosts(ing),
		})
	}
	for _, tlsEntry := range ing.Spec.TLS {
		if tlsEntry.SecretName == "" {
			continue
		}
		secret, err := cs.CoreV1().Secrets(ing.Namespace).Get(ctx, tlsEntry.SecretName, metav1.GetOptions{})
		if err != nil {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ing.Namespace,
				Name:           ing.Name,
				Severity:       SeverityCritical,
				Category:       "networking",
				Check:          "ingress-tls-secret",
				Summary:        fmt.Sprintf("TLS secret %s is missing", tlsEntry.SecretName),
				Recommendation: "Create or restore the referenced TLS secret and verify cert-manager or secret sync automation.",
			})
			continue
		}
		issues = append(issues, ingressCertificateIssues(ing, ns, *secret, tlsEntry.SecretName)...)
	}
	return issues
}

func checkIngressExternalExposure(ing networkingv1.Ingress, ns namespaceMeta, services map[string]corev1.Service) []Issue {
	issues := make([]Issue, 0)
	public := ingressLooksPublic(ing)
	if !public {
		return issues
	}
	if insecureRedirectDisabled(ing.Annotations) {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "ingress-insecure-redirects",
			Summary:        "ingress disables or weakens HTTPS redirect behavior",
			Recommendation: "Enable forced HTTP->HTTPS redirects and disable plain HTTP exposure for public ingress entrypoints.",
		})
	}
	if ingressHasTLS(ing) && !hasStrictTransportSecurity(ing.Annotations) {
		severity := SeverityWarning
		if isProductionNamespace(ns) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "ingress-missing-hsts",
			Summary:        "public TLS ingress is missing obvious HSTS configuration",
			Recommendation: "Set Strict-Transport-Security headers on public HTTPS ingress endpoints so browsers refuse insecure downgrades.",
		})
	}
	if adminPaths := publicAdminPaths(ing, services); len(adminPaths) > 0 && !ingressAuthConfigured(ing) {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "ingress-admin-path-public",
			Summary:        fmt.Sprintf("public ingress exposes admin or operational paths: %s", strings.Join(adminPaths, ", ")),
			Recommendation: "Move admin, debug, and dashboard paths behind authentication or private/internal ingress exposure only.",
		})
	}
	if wildcardHosts := wildcardIngressHosts(ing); len(wildcardHosts) > 0 && !ingressAuthConfigured(ing) && !ingressHasSourceControls(ing.Annotations) {
		severity := SeverityWarning
		if isProductionNamespace(ns) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "ingress-wildcard-public",
			Summary:        fmt.Sprintf("wildcard hosts are exposed without obvious auth or source restrictions: %s", strings.Join(wildcardHosts, ", ")),
			Recommendation: "Avoid unrestricted wildcard hosts on public ingress; require auth, source allowlists, or split high-risk hosts onto dedicated ingress resources.",
		})
	}
	if findings := dangerousIngressAnnotations(ing.Annotations); len(findings) > 0 {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "ingress-dangerous-annotations",
			Summary:        fmt.Sprintf("ingress uses controller annotations that can weaken edge security: %s", strings.Join(findings, ", ")),
			Recommendation: "Remove arbitrary snippet annotations and unsafe TLS/proxy overrides from ingress resources unless they are explicitly reviewed and tightly controlled.",
		})
	}
	issues = append(issues, weakTLSAnnotationIssues("Ingress", ing.Namespace, ing.Name, ing.Annotations)...)
	return issues
}

func probeIngressHandshake(ing networkingv1.Ingress) []Issue {
	target, serverName := ingressProbeTarget(ing)
	if target == "" {
		return nil
	}
	hostPort := net.JoinHostPort(target, "443")
	start := time.Now()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tlsConfig := &tls.Config{ServerName: serverName}
	if TLSProbeMode() == "handshake-only" {
		tlsConfig.InsecureSkipVerify = true
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", hostPort, tlsConfig)
	if err != nil {
		return []Issue{{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityWarning,
			Category:       "networking",
			Check:          "ingress-handshake",
			Detection:      "active-probe",
			Confidence:     "medium",
			Summary:        fmt.Sprintf("TLS handshake to %s failed: %v", target, err),
			Recommendation: "Check ingress listener reachability, LB security groups/firewall rules, and certificate chain.",
		}}
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	issues := make([]Issue, 0)
	latency := time.Since(start)
	if latency > 1500*time.Millisecond {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityWarning,
			Category:       "networking",
			Check:          "ingress-handshake-latency",
			Detection:      "active-probe",
			Confidence:     "medium",
			Summary:        fmt.Sprintf("TLS handshake to %s is slow (~%dms)", target, latency.Milliseconds()),
			Recommendation: "Investigate load balancer health, upstream connectivity, and TLS termination performance.",
			References:     []string{"tcp/443"},
		})
	}
	if state.Version > 0 && state.Version < tls.VersionTLS12 {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "ingress-tls-legacy-version",
			Summary:        fmt.Sprintf("ingress negotiated legacy TLS version %s", tlsVersionName(state.Version)),
			Recommendation: "Disable TLS 1.0/1.1 on the edge and enforce TLS 1.2+ with modern cipher suites.",
		})
	}
	if isWeakCipherSuite(state.CipherSuite) {
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "ingress-tls-weak-cipher",
			Summary:        fmt.Sprintf("ingress negotiated weak TLS cipher suite %s", tls.CipherSuiteName(state.CipherSuite)),
			Recommendation: "Remove weak cipher suites such as RC4, 3DES, CBC-only legacy sets, and NULL/MD5-based suites from ingress TLS policy.",
		})
	}
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		legacyTLSConfig := &tls.Config{ServerName: serverName, MinVersion: version, MaxVersion: version}
		if TLSProbeMode() == "handshake-only" {
			legacyTLSConfig.InsecureSkipVerify = true
		}
		legacyConn, err := tls.DialWithDialer(dialer, "tcp", hostPort, legacyTLSConfig)
		if err != nil {
			continue
		}
		_ = legacyConn.Close()
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Namespace:      ing.Namespace,
			Name:           ing.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "ingress-tls-legacy-version",
			Summary:        fmt.Sprintf("ingress still accepts legacy TLS version %s", tlsVersionName(version)),
			Recommendation: "Disable TLS 1.0/1.1 on the ingress listener or load balancer security policy.",
		})
	}
	return dedupeIssues(issues)
}

func checkGatewayExposure(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string, namespaces map[string]namespaceMeta) []Issue {
	if dyn == nil {
		return nil
	}
	gateways, err := dyn.Resource(gatewayGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return []Issue{{
			Kind:           "Gateway",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "gateway-api-query",
			Summary:        fmt.Sprintf("unable to inspect Gateway API resources: %v", err),
			Recommendation: "Verify the gateway.networking.k8s.io API is available and readable if you rely on Gateway API for north-south traffic.",
		}}
	}
	routes, routeErr := dyn.Resource(httpRouteGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if routeErr != nil && !apierrors.IsNotFound(routeErr) {
		routes = &unstructured.UnstructuredList{}
	}
	return gatewayExposureIssues(ctx, cs, gateways.Items, routes.Items, namespaces)
}

func gatewayExposureIssues(ctx context.Context, cs *kubernetes.Clientset, gateways, routes []unstructured.Unstructured, namespaces map[string]namespaceMeta) []Issue {
	routesByGateway := indexHTTPRoutesByGateway(routes)
	issues := make([]Issue, 0)
	for _, gateway := range gateways {
		nsMeta := namespaces[gateway.GetNamespace()]
		public := gatewayLooksPublic(gateway)
		listeners := gatewayListeners(gateway)
		if public && gatewayHasPlainHTTPListener(listeners) {
			severity := SeverityWarning
			if isProductionNamespace(nsMeta) {
				severity = SeverityCritical
			}
			issues = append(issues, Issue{
				Kind:           "Gateway",
				Namespace:      gateway.GetNamespace(),
				Name:           gateway.GetName(),
				Severity:       severity,
				Category:       "security",
				Check:          "gateway-no-tls",
				Summary:        "public gateway exposes HTTP listeners without TLS termination",
				Recommendation: "Use HTTPS or TLS listeners for public Gateway API entrypoints and redirect plain HTTP to HTTPS.",
			})
		}
		if public && gatewayHasTLSListener(listeners) && !hasStrictTransportSecurity(gateway.GetAnnotations()) {
			issues = append(issues, Issue{
				Kind:           "Gateway",
				Namespace:      gateway.GetNamespace(),
				Name:           gateway.GetName(),
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "gateway-missing-hsts",
				Summary:        "public gateway has TLS listeners without obvious HSTS configuration",
				Recommendation: "Configure HSTS at the gateway listener or underlying data-plane policy for public HTTPS hosts.",
			})
		}
		if public && gatewayHasWildcardListener(listeners) && !ingressHasSourceControls(gateway.GetAnnotations()) {
			severity := SeverityWarning
			if isProductionNamespace(nsMeta) {
				severity = SeverityCritical
			}
			issues = append(issues, Issue{
				Kind:           "Gateway",
				Namespace:      gateway.GetNamespace(),
				Name:           gateway.GetName(),
				Severity:       severity,
				Category:       "security",
				Check:          "gateway-wildcard-public",
				Summary:        "gateway exposes wildcard hostnames without obvious source restrictions",
				Recommendation: "Restrict wildcard gateway listeners with auth, allowlists, or dedicated internal gateways where possible.",
			})
		}
		if findings := dangerousIngressAnnotations(gateway.GetAnnotations()); len(findings) > 0 {
			issues = append(issues, Issue{
				Kind:           "Gateway",
				Namespace:      gateway.GetNamespace(),
				Name:           gateway.GetName(),
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "gateway-dangerous-annotations",
				Summary:        fmt.Sprintf("gateway uses security-sensitive controller annotations: %s", strings.Join(findings, ", ")),
				Recommendation: "Review gateway annotations for arbitrary snippets, unsafe proxy settings, or controller overrides that bypass standard edge policy.",
			})
		}
		issues = append(issues, weakTLSAnnotationIssues("Gateway", gateway.GetNamespace(), gateway.GetName(), gateway.GetAnnotations())...)
		issues = append(issues, gatewayListenerTLSIssues(ctx, cs, gateway, listeners, nsMeta)...)
		if public {
			issues = append(issues, publicGatewayAdminRouteIssues(gateway, routesByGateway[gateway.GetNamespace()+"/"+gateway.GetName()])...)
		}
	}
	return dedupeIssues(issues)
}

func ingressCertificateIssues(ing networkingv1.Ingress, ns namespaceMeta, secret corev1.Secret, secretName string) []Issue {
	certs := parsePEMCertificates(secret.Data["tls.crt"])
	issues := make([]Issue, 0)
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		if time.Until(cert.NotAfter) <= 0 {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ing.Namespace,
				Name:           ing.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "ingress-tls-expired",
				Summary:        fmt.Sprintf("ingress TLS certificate in secret %s is expired (CN=%s, notAfter=%s)", secretName, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
				Recommendation: "Rotate the ingress certificate immediately and verify the issuance/renewal chain before re-exposing this endpoint.",
			})
		}
		if finding := weakCertificateFinding(cert); finding != "" {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ing.Namespace,
				Name:           ing.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "ingress-tls-weak-crypto",
				Summary:        finding,
				Recommendation: "Reissue ingress certificates with TLS 1.2+/modern cipher compatibility, strong key sizes, and a current signature algorithm.",
			})
		}
		if isSelfSignedCertificate(cert) && isProductionNamespace(ns) {
			issues = append(issues, Issue{
				Kind:           "Ingress",
				Namespace:      ing.Namespace,
				Name:           ing.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "ingress-tls-self-signed",
				Summary:        fmt.Sprintf("production ingress uses a self-signed certificate (CN=%s, secret=%s)", cert.Subject.CommonName, secretName),
				Recommendation: "Use certificates issued by a trusted internal or public CA for production ingress endpoints and rotate self-signed material out of the path.",
			})
		}
	}
	return issues
}

func gatewayListenerTLSIssues(ctx context.Context, cs *kubernetes.Clientset, gateway unstructured.Unstructured, listeners []gatewayListener, ns namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, listener := range listeners {
		issues = append(issues, weakTLSOptionIssues("Gateway", gateway.GetNamespace(), gateway.GetName(), listener.options)...)
		for _, secretName := range listener.certificateRefs {
			secret, err := cs.CoreV1().Secrets(gateway.GetNamespace()).Get(ctx, secretName, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					issues = append(issues, Issue{
						Kind:           "Gateway",
						Namespace:      gateway.GetNamespace(),
						Name:           gateway.GetName(),
						Severity:       SeverityCritical,
						Category:       "security",
						Check:          "gateway-tls-secret",
						Summary:        fmt.Sprintf("gateway listener %s references missing TLS secret %s", listener.name, secretName),
						Recommendation: "Restore the referenced TLS secret or update Gateway listener certificateRefs to valid secrets.",
					})
				}
				continue
			}
			for _, cert := range parsePEMCertificates(secret.Data["tls.crt"]) {
				if cert == nil {
					continue
				}
				if time.Until(cert.NotAfter) <= 0 {
					issues = append(issues, Issue{
						Kind:           "Gateway",
						Namespace:      gateway.GetNamespace(),
						Name:           gateway.GetName(),
						Severity:       SeverityCritical,
						Category:       "security",
						Check:          "gateway-tls-expired",
						Summary:        fmt.Sprintf("gateway TLS secret %s is expired (CN=%s)", secretName, cert.Subject.CommonName),
						Recommendation: "Rotate the gateway certificate immediately and verify external clients trust the new chain.",
					})
				}
				if finding := weakCertificateFinding(cert); finding != "" {
					issues = append(issues, Issue{
						Kind:           "Gateway",
						Namespace:      gateway.GetNamespace(),
						Name:           gateway.GetName(),
						Severity:       SeverityWarning,
						Category:       "security",
						Check:          "gateway-tls-weak-crypto",
						Summary:        finding,
						Recommendation: "Reissue Gateway API listener certificates with modern signature algorithms and key sizes.",
					})
				}
				if isSelfSignedCertificate(cert) && isProductionNamespace(ns) {
					issues = append(issues, Issue{
						Kind:           "Gateway",
						Namespace:      gateway.GetNamespace(),
						Name:           gateway.GetName(),
						Severity:       SeverityCritical,
						Category:       "security",
						Check:          "gateway-tls-self-signed",
						Summary:        fmt.Sprintf("production gateway uses self-signed TLS material in secret %s", secretName),
						Recommendation: "Use trusted CA-issued certificates for production Gateway API listeners instead of self-signed material.",
					})
				}
			}
		}
	}
	return issues
}

func weakTLSAnnotationIssues(kind, namespace, name string, annotations map[string]string) []Issue {
	issues := make([]Issue, 0)
	findings := make([]string, 0)
	for key, value := range annotations {
		combined := strings.ToLower(key + "=" + value)
		if strings.Contains(combined, "ssl-protocols") || strings.Contains(combined, "ssl-min-ver") || strings.Contains(combined, "ssl-policy") || strings.Contains(combined, "tls.options") {
			if hasLegacyTLSVersion(value) {
				findings = append(findings, key+"="+value)
			}
		}
		if strings.Contains(combined, "ssl-ciphers") || strings.Contains(combined, "cipher") {
			if hasWeakCipherString(value) {
				findings = append(findings, key+"="+value)
			}
		}
	}
	if len(findings) > 0 {
		issues = append(issues, Issue{
			Kind:           kind,
			Namespace:      namespace,
			Name:           name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          strings.ToLower(kind) + "-tls-weak-policy",
			Summary:        fmt.Sprintf("%s annotations allow legacy TLS settings: %s", strings.ToLower(kind), strings.Join(uniqueStrings(findings), ", ")),
			Recommendation: "Tighten edge TLS policy to TLS 1.2+ and remove weak/legacy cipher or compatibility profiles from controller annotations.",
		})
	}
	return issues
}

func weakTLSOptionIssues(kind, namespace, name string, options map[string]string) []Issue {
	if len(options) == 0 {
		return nil
	}
	findings := make([]string, 0)
	for key, value := range options {
		if hasLegacyTLSVersion(value) || hasWeakCipherString(value) {
			findings = append(findings, key+"="+value)
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
		Check:          strings.ToLower(kind) + "-tls-weak-policy",
		Summary:        fmt.Sprintf("%s listener options allow legacy TLS settings: %s", strings.ToLower(kind), strings.Join(uniqueStrings(findings), ", ")),
		Recommendation: "Use TLS 1.2+ minimum versions and remove weak ciphers from Gateway API listener TLS options.",
	}}
}

func loadBalancerInternalExposureIssues(services []corev1.Service, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, service := range services {
		if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if serviceHasAllowlist(service) {
			continue
		}
		if !serviceLooksInternalOnly(service) {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[service.Namespace]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Service",
			Namespace:      service.Namespace,
			Name:           service.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "loadbalancer-internal-app-public",
			Summary:        "LoadBalancer service for an internal-only application appears publicly exposed",
			Recommendation: "Switch the service to an internal load balancer, add source allowlists, or keep internal-only apps behind private ingress/VPN paths.",
		})
	}
	return issues
}

func nodePortSensitiveExposureIssues(services []corev1.Service, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, service := range services {
		if service.Spec.Type != corev1.ServiceTypeNodePort {
			continue
		}
		if !serviceLooksSensitive(service, namespaces[service.Namespace]) {
			continue
		}
		nodePorts := make([]string, 0)
		for _, port := range service.Spec.Ports {
			if port.NodePort > 0 {
				nodePorts = append(nodePorts, fmt.Sprintf("%s:%d", port.Name, port.NodePort))
			}
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[service.Namespace]) || serviceLooksInternalOnly(service) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Service",
			Namespace:      service.Namespace,
			Name:           service.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "nodeport-sensitive-service",
			Summary:        fmt.Sprintf("sensitive service is exposed through NodePort: %s", strings.Join(uniqueStrings(nodePorts), ", ")),
			Recommendation: "Avoid NodePort on sensitive services; prefer private ingress, internal load balancers, or cluster-internal Service types with explicit north-south controls.",
		})
	}
	return issues
}

func ingressNeedsTLS(ing networkingv1.Ingress) bool {
	return len(ingressHosts(ing)) > 0 && !ingressHasTLS(ing)
}

func ingressHasTLS(ing networkingv1.Ingress) bool {
	return len(ing.Spec.TLS) > 0
}

func ingressHosts(ing networkingv1.Ingress) []string {
	hosts := make([]string, 0)
	for _, rule := range ing.Spec.Rules {
		if strings.TrimSpace(rule.Host) != "" {
			hosts = append(hosts, rule.Host)
		}
	}
	for _, entry := range ing.Spec.TLS {
		hosts = append(hosts, entry.Hosts...)
	}
	return uniqueStrings(hosts)
}

func wildcardIngressHosts(ing networkingv1.Ingress) []string {
	wildcards := make([]string, 0)
	for _, host := range ingressHosts(ing) {
		if strings.HasPrefix(strings.TrimSpace(host), "*.") {
			wildcards = append(wildcards, host)
		}
	}
	return uniqueStrings(wildcards)
}

func publicAdminPaths(ing networkingv1.Ingress, services map[string]corev1.Service) []string {
	findings := make([]string, 0)
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			fields := []string{rule.Host, path.Path}
			if path.Backend.Service != nil {
				fields = append(fields, path.Backend.Service.Name)
				if service, ok := services[ing.Namespace+"/"+path.Backend.Service.Name]; ok {
					fields = append(fields, service.Name)
					for key, value := range service.Labels {
						fields = append(fields, key, value)
					}
				}
			}
			text := strings.ToLower(strings.Join(fields, " "))
			for _, marker := range []string{"/admin", "/debug", "/pprof", "/actuator", "/metrics", "dashboard", "grafana", "argocd", "jenkins", "prometheus", "kibana", "admin"} {
				if strings.Contains(text, marker) {
					findings = append(findings, strings.TrimSpace(rule.Host+path.Path))
					break
				}
			}
		}
	}
	return uniqueStrings(findings)
}

func dangerousIngressAnnotations(annotations map[string]string) []string {
	findings := make([]string, 0)
	for key, value := range annotations {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(strings.TrimSpace(value))
		switch {
		case strings.Contains(keyLower, "configuration-snippet"), strings.Contains(keyLower, "server-snippet"), strings.Contains(keyLower, "location-snippet"), strings.Contains(keyLower, "auth-snippet"):
			findings = append(findings, key)
		case strings.Contains(keyLower, "proxy-ssl-verify") && valueLower == "off":
			findings = append(findings, key+"=off")
		case strings.Contains(keyLower, "auth-tls-verify-client") && (valueLower == "off" || valueLower == "optional_no_ca"):
			findings = append(findings, key+"="+value)
		}
	}
	return uniqueStrings(findings)
}

func insecureRedirectDisabled(annotations map[string]string) bool {
	for key, value := range annotations {
		combined := strings.ToLower(key + "=" + strings.TrimSpace(value))
		for _, marker := range []string{"ssl-redirect=false", "force-ssl-redirect=false", "redirect-to-https=false", "allow-http=true"} {
			if strings.Contains(combined, marker) {
				return true
			}
		}
	}
	return false
}

func hasStrictTransportSecurity(annotations map[string]string) bool {
	for key, value := range annotations {
		combined := strings.ToLower(key + "=" + value)
		if strings.Contains(combined, "strict-transport-security") || strings.Contains(combined, "hsts") {
			if !strings.Contains(combined, "false") && !strings.Contains(combined, "off") {
				return true
			}
		}
	}
	return false
}

func ingressHasSourceControls(annotations map[string]string) bool {
	for key, value := range annotations {
		combined := strings.ToLower(key + "=" + value)
		for _, marker := range []string{"whitelist-source-range", "allowlist", "load-balancer-source-ranges", "loadbalancersourceranges", "scheme=internal", "internal-load-balancer"} {
			if strings.Contains(combined, marker) {
				return true
			}
		}
	}
	return false
}

func ingressLooksSensitive(ing networkingv1.Ingress) bool {
	fields := []string{ing.Name, ing.Namespace}
	for _, host := range ingressHosts(ing) {
		fields = append(fields, host)
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			fields = append(fields, path.Path)
			if path.Backend.Service != nil {
				fields = append(fields, path.Backend.Service.Name)
			}
		}
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"auth", "identity", "payment", "secret", "vault", "token", "admin", "dashboard", "gateway"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func ingressProbeTarget(ing networkingv1.Ingress) (string, string) {
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		return "", ""
	}
	target := ing.Status.LoadBalancer.Ingress[0].Hostname
	if target == "" {
		target = ing.Status.LoadBalancer.Ingress[0].IP
	}
	serverName := ""
	for _, host := range ingressHosts(ing) {
		if host != "" && !strings.Contains(host, "*") {
			serverName = host
			break
		}
	}
	return target, serverName
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

func hasLegacyTLSVersion(value string) bool {
	text := strings.ToLower(value)
	for _, marker := range []string{"tlsv1 ", "tlsv1,", "tlsv1.0", "tlsv1.1", "1.0", "1.1", "2015-04", "2015-05", "2016-08"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func hasWeakCipherString(value string) bool {
	text := strings.ToLower(value)
	for _, marker := range []string{"3des", "rc4", "des", "md5", "null", "anon", "cbc3"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func isWeakCipherSuite(cipher uint16) bool {
	name := strings.ToLower(tls.CipherSuiteName(cipher))
	return hasWeakCipherString(name)
}

func isSelfSignedCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.Issuer.String() == cert.Subject.String() && cert.CheckSignatureFrom(cert) == nil
}

func serviceLooksInternalOnly(service corev1.Service) bool {
	if looksLikeAdminUI(service.Name, service.Labels) || len(serviceDebugPorts(service)) > 0 {
		return true
	}
	fields := []string{service.Name, service.Namespace}
	for _, source := range []map[string]string{service.Labels, service.Annotations} {
		for key, value := range source {
			fields = append(fields, key, value)
		}
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"internal", "private", "cluster-local", "intranet", "backoffice", "back-office", "corp", "admin", "dashboard"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func serviceLooksSensitive(service corev1.Service, ns namespaceMeta) bool {
	if serviceLooksInternalOnly(service) || isProductionNamespace(ns) && len(serviceDebugPorts(service)) > 0 {
		return true
	}
	fields := []string{service.Name, service.Namespace}
	for _, port := range service.Spec.Ports {
		fields = append(fields, port.Name)
	}
	for _, source := range []map[string]string{service.Labels, service.Annotations} {
		for key, value := range source {
			fields = append(fields, key, value)
		}
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"auth", "identity", "payment", "secret", "vault", "token", "metrics", "debug", "gateway", "ingress"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

type gatewayListener struct {
	name            string
	hostname        string
	protocol        string
	certificateRefs []string
	options         map[string]string
}

type httpRouteSummary struct {
	hostnames []string
	paths     []string
}

func gatewayLooksPublic(gateway unstructured.Unstructured) bool {
	annotations := gateway.GetAnnotations()
	if ingressHasSourceControls(annotations) {
		return false
	}
	for _, source := range []map[string]string{gateway.GetLabels(), annotations} {
		for key, value := range source {
			combined := strings.ToLower(key + "=" + value)
			if strings.Contains(combined, "internal") || strings.Contains(combined, "private") {
				return false
			}
		}
	}
	return len(gatewayListeners(gateway)) > 0
}

func gatewayListeners(gateway unstructured.Unstructured) []gatewayListener {
	items, found, err := unstructured.NestedSlice(gateway.Object, "spec", "listeners")
	if err != nil || !found {
		return nil
	}
	listeners := make([]gatewayListener, 0, len(items))
	for _, item := range items {
		listenerMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		listener := gatewayListener{
			name:     nestedStringMapValue(listenerMap, "name"),
			hostname: nestedStringMapValue(listenerMap, "hostname"),
			protocol: strings.ToUpper(nestedStringMapValue(listenerMap, "protocol")),
			options:  nestedStringMap(listenerMap, "tls", "options"),
		}
		refs, foundRefs, _ := unstructured.NestedSlice(listenerMap, "tls", "certificateRefs")
		if foundRefs {
			for _, ref := range refs {
				refMap, ok := ref.(map[string]any)
				if !ok {
					continue
				}
				name := nestedStringMapValue(refMap, "name")
				if strings.TrimSpace(name) != "" {
					listener.certificateRefs = append(listener.certificateRefs, name)
				}
			}
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

func gatewayHasPlainHTTPListener(listeners []gatewayListener) bool {
	for _, listener := range listeners {
		if listener.protocol == "HTTP" {
			return true
		}
	}
	return false
}

func gatewayHasTLSListener(listeners []gatewayListener) bool {
	for _, listener := range listeners {
		if listener.protocol == "HTTPS" || listener.protocol == "TLS" {
			return true
		}
	}
	return false
}

func gatewayHasWildcardListener(listeners []gatewayListener) bool {
	for _, listener := range listeners {
		if strings.HasPrefix(strings.TrimSpace(listener.hostname), "*.") {
			return true
		}
	}
	return false
}

func indexHTTPRoutesByGateway(routes []unstructured.Unstructured) map[string][]httpRouteSummary {
	index := make(map[string][]httpRouteSummary)
	for _, route := range routes {
		hostnames, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
		paths := httpRoutePaths(route)
		parentRefs, found, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
		if !found {
			continue
		}
		for _, ref := range parentRefs {
			refMap, ok := ref.(map[string]any)
			if !ok {
				continue
			}
			name := nestedStringMapValue(refMap, "name")
			if name == "" {
				continue
			}
			namespace := nestedStringMapValue(refMap, "namespace")
			if namespace == "" {
				namespace = route.GetNamespace()
			}
			key := namespace + "/" + name
			index[key] = append(index[key], httpRouteSummary{hostnames: hostnames, paths: paths})
		}
	}
	return index
}

func httpRoutePaths(route unstructured.Unstructured) []string {
	rules, found, err := unstructured.NestedSlice(route.Object, "spec", "rules")
	if err != nil || !found {
		return nil
	}
	paths := make([]string, 0)
	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		matches, found, _ := unstructured.NestedSlice(ruleMap, "matches")
		if !found {
			continue
		}
		for _, match := range matches {
			matchMap, ok := match.(map[string]any)
			if !ok {
				continue
			}
			pathType := nestedStringMapValue(matchMap, "path", "type")
			pathValue := nestedStringMapValue(matchMap, "path", "value")
			if pathValue != "" {
				paths = append(paths, strings.TrimSpace(pathType+":"+pathValue))
			}
		}
	}
	return uniqueStrings(paths)
}

func publicGatewayAdminRouteIssues(gateway unstructured.Unstructured, routes []httpRouteSummary) []Issue {
	findings := make([]string, 0)
	for _, route := range routes {
		for _, host := range route.hostnames {
			for _, marker := range []string{"admin", "dashboard", "grafana", "argocd", "jenkins", "prometheus", "kibana"} {
				if strings.Contains(strings.ToLower(host), marker) {
					findings = append(findings, host)
					break
				}
			}
		}
		for _, path := range route.paths {
			text := strings.ToLower(path)
			for _, marker := range []string{"/admin", "/debug", "/pprof", "/metrics", "/actuator"} {
				if strings.Contains(text, marker) {
					findings = append(findings, path)
					break
				}
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	items := uniqueStrings(findings)
	sort.Strings(items)
	return []Issue{{
		Kind:           "Gateway",
		Namespace:      gateway.GetNamespace(),
		Name:           gateway.GetName(),
		Severity:       SeverityCritical,
		Category:       "security",
		Check:          "gateway-admin-path-public",
		Summary:        fmt.Sprintf("public gateway routes admin or operational paths: %s", strings.Join(items, ", ")),
		Recommendation: "Do not publish admin, metrics, debug, or dashboard routes on public gateways without strong authentication and source restrictions.",
	}}
}

func nestedStringMap(source map[string]any, fields ...string) map[string]string {
	value, found, err := unstructured.NestedStringMap(source, fields...)
	if err != nil || !found {
		return nil
	}
	return value
}

func nestedStringMapValue(source map[string]any, fields ...string) string {
	value, found, err := unstructured.NestedString(source, fields...)
	if err != nil || !found {
		return ""
	}
	return value
}
