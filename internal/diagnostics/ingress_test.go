package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestIngressHelpers(t *testing.T) {
	pathType := networkingv1.PathTypePrefix
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grafana-admin",
			Namespace: "prod",
			Annotations: map[string]string{
				"ssl-redirect":          "false",
				"ssl-ciphers":           "RC4",
				"configuration-snippet": "bad",
				"hsts":                  "true",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "10.0.0.0/8",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "api.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
					Path:     "/admin",
					PathType: &pathType,
					Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
				}}}},
			}},
			TLS: []networkingv1.IngressTLS{{Hosts: []string{"*.example.com", "api.example.com"}, SecretName: "tls-secret"}},
		},
		Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "lb.example.com"}}}},
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod", Labels: map[string]string{"app": "grafana"}, Annotations: map[string]string{"scheme": "internal"}},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Ports: []corev1.ServicePort{{Name: "metrics", Port: 9090, NodePort: 30090}}},
	}
	ns := namespaceMeta{name: "prod", labels: map[string]string{"environment": "production"}}

	if !ingressHasTLS(ing) || ingressNeedsTLS(ing) || len(ingressHosts(ing)) < 2 || len(wildcardIngressHosts(ing)) != 1 {
		t.Fatal("unexpected ingress TLS helpers")
	}
	if len(publicAdminPaths(ing, map[string]corev1.Service{"prod/grafana": service})) == 0 || len(dangerousIngressAnnotations(ing.Annotations)) == 0 {
		t.Fatal("expected ingress admin and annotation findings")
	}
	if !insecureRedirectDisabled(ing.Annotations) || !hasStrictTransportSecurity(ing.Annotations) || !ingressHasSourceControls(ing.Annotations) || !ingressLooksSensitive(ing) {
		t.Fatal("unexpected ingress helper booleans")
	}
	if target, serverName := ingressProbeTarget(ing); target == "" || serverName == "" {
		t.Fatal("expected ingress probe target")
	}
	if tlsVersionName(0x9999) == "" || !hasLegacyTLSVersion("TLSv1.0") || !hasWeakCipherString("RC4-SHA") || !isWeakCipherSuite(0x000a) {
		t.Fatal("unexpected TLS helper behavior")
	}
	if !serviceLooksInternalOnly(service) || !serviceLooksSensitive(service, ns) {
		t.Fatal("expected sensitive service helpers")
	}
	if len(weakTLSAnnotationIssues("Ingress", "prod", "grafana", map[string]string{"ssl-protocols": "TLSv1.0", "ssl-ciphers": "RC4"})) == 0 {
		t.Fatal("expected weak tls annotation issues")
	}
	if len(weakTLSOptionIssues("Gateway", "prod", "gw", map[string]string{"minVersion": "1.0"})) == 0 {
		t.Fatal("expected weak tls option issues")
	}
	services := []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Name: "admin-internal", Namespace: "prod", Labels: map[string]string{"app": "admin"}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}},
		service,
	}
	if len(loadBalancerInternalExposureIssues(services, map[string]namespaceMeta{"prod": ns})) == 0 {
		t.Fatal("expected internal lb exposure issue")
	}
	if len(nodePortSensitiveExposureIssues([]corev1.Service{service}, map[string]namespaceMeta{"prod": ns})) == 0 {
		t.Fatal("expected nodeport sensitive service issue")
	}

	expiredCert := generateSelfSignedCertPEM(t, "grafana", time.Now().Add(-time.Hour))
	ingTLSIssues := ingressCertificateIssues(ing, ns, corev1.Secret{Data: map[string][]byte{"tls.crt": expiredCert}}, "tls-secret")
	if len(ingTLSIssues) == 0 {
		t.Fatal("expected ingress certificate issues")
	}

	gateway := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata": map[string]any{
			"name":      "public-gw",
			"namespace": "prod",
			"annotations": map[string]any{
				"hsts": "true",
			},
		},
		"spec": map[string]any{
			"listeners": []any{
				map[string]any{"name": "http", "hostname": "*.example.com", "protocol": "HTTP"},
				map[string]any{"name": "https", "hostname": "api.example.com", "protocol": "HTTPS", "tls": map[string]any{"certificateRefs": []any{map[string]any{"name": "gw-tls"}}, "options": map[string]any{"minVersion": "1.0"}}},
			},
		},
	}}
	route := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]any{
			"name":      "admin-route",
			"namespace": "prod",
		},
		"spec": map[string]any{
			"hostnames":  []any{"admin.example.com"},
			"parentRefs": []any{map[string]any{"name": "public-gw"}},
			"rules":      []any{map[string]any{"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/metrics"}}}}},
		},
	}}
	listeners := gatewayListeners(gateway)
	if !gatewayLooksPublic(gateway) || len(listeners) != 2 || !gatewayHasPlainHTTPListener(listeners) || !gatewayHasTLSListener(listeners) || !gatewayHasWildcardListener(listeners) {
		t.Fatal("unexpected gateway helper behavior")
	}
	indexed := indexHTTPRoutesByGateway([]unstructured.Unstructured{route})
	if len(indexed["prod/public-gw"]) != 1 || len(httpRoutePaths(route)) != 1 {
		t.Fatal("expected indexed gateway routes")
	}
	if len(publicGatewayAdminRouteIssues(gateway, indexed["prod/public-gw"])) == 0 {
		t.Fatal("expected gateway admin route issue")
	}
	if nestedStringMapValue(gateway.Object, "metadata", "name") != "public-gw" || nestedStringMap(gateway.Object, "metadata", "labels") != nil {
		t.Fatal("unexpected nested map helpers")
	}
}

func TestCheckIngresses(t *testing.T) {
	ctx := context.Background()
	pathType := networkingv1.PathTypePrefix
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/apis/networking.k8s.io/v1/namespaces/prod/ingresses":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.IngressList{Items: []networkingv1.Ingress{{
				ObjectMeta: metav1.ObjectMeta{Name: "public-ing", Namespace: "prod", Annotations: map[string]string{"ssl-redirect": "false"}},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{{
						Host: "admin.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/admin",
							PathType: &pathType,
							Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
						}}}},
					}},
				},
			}}})
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod", Labels: map[string]string{"app": "grafana"}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{{Name: "metrics", Port: 9090}}}}}})
		case "/apis/apps/v1/deployments":
			replicas := int32(2)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "nginx-ingress-controller", Namespace: metav1.NamespaceSystem}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{AvailableReplicas: 1}}}})
		case "/api/v1/namespaces/prod/services/grafana":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod"}})
		case "/api/v1/namespaces/prod/endpoints/grafana":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Endpoints{})
		case "/api/v1/namespaces/prod/secrets/tls-secret":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckIngresses(ctx, cs, nil, "prod")
	if err != nil {
		t.Fatalf("CheckIngresses returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several ingress issues, got %+v", issues)
	}
	if _, err := CheckIngresses(ctx, nil, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}

func TestIngressGatewayAndExposurePaths(t *testing.T) {
	ctx := context.Background()
	pathType := networkingv1.PathTypePrefix
	ns := namespaceMeta{name: "prod", labels: map[string]string{"environment": "production"}}
	ingNoTLS := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "public-no-tls", Namespace: "prod"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "admin.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
					Path:     "/admin",
					PathType: &pathType,
					Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
				}}}},
			}},
		},
	}
	ingTLS := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "public-tls",
			Namespace: "prod",
			Annotations: map[string]string{
				"ssl-redirect":          "false",
				"configuration-snippet": "bad",
				"ssl-ciphers":           "RC4",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "*.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
					Path:     "/admin",
					PathType: &pathType,
					Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
				}}}},
			}},
			TLS: []networkingv1.IngressTLS{{Hosts: []string{"admin.example.com", "*.example.com"}, SecretName: "missing-tls"}},
		},
	}
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/secrets/missing-tls":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		case "/api/v1/namespaces/prod/secrets/gw-tls":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	if len(checkIngressTLS(ctx, cs, ingNoTLS, ns)) == 0 || len(checkIngressTLS(ctx, cs, ingTLS, ns)) == 0 {
		t.Fatal("expected ingress TLS checks to report issues")
	}
	serviceMap := map[string]corev1.Service{
		"prod/grafana": {
			ObjectMeta: metav1.ObjectMeta{
				Name:        "grafana",
				Namespace:   "prod",
				Labels:      map[string]string{"app": "grafana"},
				Annotations: map[string]string{"scheme": "internal"},
			},
			Spec: corev1.ServiceSpec{
				Type:  corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{{Name: "https", Port: 443, NodePort: 30443}},
			},
		},
	}
	if len(checkIngressExternalExposure(ingTLS, ns, serviceMap)) < 4 {
		t.Fatal("expected external exposure checks to report multiple issues")
	}

	gateway := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata": map[string]any{
			"name":      "public-gw",
			"namespace": "prod",
			"annotations": map[string]any{
				"configuration-snippet": "bad",
				"ssl-ciphers":           "RC4",
			},
		},
		"spec": map[string]any{
			"listeners": []any{
				map[string]any{"name": "http", "hostname": "*.example.com", "protocol": "HTTP"},
				map[string]any{
					"name":     "https",
					"hostname": "admin.example.com",
					"protocol": "HTTPS",
					"tls": map[string]any{
						"certificateRefs": []any{map[string]any{"name": "gw-tls"}},
						"options":         map[string]any{"minVersion": "1.0"},
					},
				},
			},
		},
	}}
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]any{
			"name":      "admin-route",
			"namespace": "prod",
		},
		"spec": map[string]any{
			"hostnames":  []any{"admin.example.com"},
			"parentRefs": []any{map[string]any{"name": "public-gw"}},
			"rules": []any{map[string]any{
				"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/admin"}}},
			}},
		},
	}}
	listeners := gatewayListeners(*gateway)
	if len(gatewayListenerTLSIssues(ctx, cs, *gateway, listeners, ns)) < 2 {
		t.Fatal("expected gateway listener TLS issues")
	}
	if len(gatewayExposureIssues(ctx, cs, []unstructured.Unstructured{*gateway}, []unstructured.Unstructured{*route}, map[string]namespaceMeta{"prod": ns})) < 5 {
		t.Fatal("expected gateway exposure issues")
	}

	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			gatewayGVR:   "GatewayList",
			httpRouteGVR: "HTTPRouteList",
		},
		gateway,
		route,
	)
	_ = checkGatewayExposure(ctx, cs, dyn, "prod", map[string]namespaceMeta{"prod": ns})

}
