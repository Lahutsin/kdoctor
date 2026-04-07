package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConfigExposureHelpers(t *testing.T) {
	pods := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}, Annotations: map[string]string{"token": "secret-token"}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Env: []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "secret"}}}},
			Containers: []corev1.Container{{
				Name:    "api",
				Image:   "api:latest",
				Args:    []string{"--debug", "--log-level=debug"},
				Env:     []corev1.EnvVar{{Name: "API_TOKEN", Value: "abc"}, {Name: "PASSWORD_FILE", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{}}}},
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}},
			}},
		},
	}}
	services := []corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod", Labels: map[string]string{"app": "grafana"}, Annotations: map[string]string{"password": "top-secret"}},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ExternalIPs: []string{"1.2.3.4"}, Ports: []corev1.ServicePort{{Name: "metrics", Port: 9090}, {Name: "admin", Port: 6060}}},
	}}
	pathType := networkingv1.PathTypePrefix
	ingresses := []networkingv1.Ingress{{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "grafana.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
						Path:     "/metrics",
						PathType: &pathType,
						Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
					}}},
				},
			}},
		},
	}}
	namespaces := map[string]namespaceMeta{"prod": {name: "prod", labels: map[string]string{"client_secret": "top-secret"}, annotations: map[string]string{"token": "secret"}}}

	if len(envSensitiveValueIssues(pods)) == 0 || len(secretLoggingRiskIssues(pods)) == 0 {
		t.Fatal("expected env and logging risk issues")
	}
	if len(publicAdminUIIssues(services, ingresses)) == 0 || len(publicDebugEndpointIssues(services, ingresses)) == 0 {
		t.Fatal("expected public admin/debug issues")
	}
	if len(metadataExposureIssues(pods, services, ingresses, namespaces)) == 0 || len(inspectConfigMapsForSecrets([]corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "prod"}, Data: map[string]string{"password": "secret"}}})) == 0 {
		t.Fatal("expected metadata/configmap issues")
	}
	if !containerLikelyLogsVerbosely(pods[0].Spec.Containers[0]) || !looksLikeAdminUI("grafana", nil) || !serviceExternallyReachable(services[0]) {
		t.Fatal("expected helper detections to be true")
	}
	if !ingressLooksPublic(ingresses[0]) || ingressAuthConfigured(ingresses[0]) == true {
		t.Fatal("unexpected ingress helper result")
	}
	if !ingressTargetsAdminUI(ingresses[0], map[string]corev1.Service{"prod/grafana": services[0]}) || !ingressTargetsDebugService(ingresses[0], map[string]corev1.Service{"prod/grafana": services[0]}) {
		t.Fatal("expected ingress target helpers to match")
	}
	if len(serviceDebugPorts(services[0])) < 2 || !looksStructuredCredential("-----BEGIN PRIVATE KEY-----") {
		t.Fatal("expected debug ports and structured credential detection")
	}
	value := "hello"
	if pointerString(&value) != "hello" || pointerString(nil) != "" {
		t.Fatal("unexpected pointerString behavior")
	}
	if !looksSensitiveConfigKey("client_secret") || !looksSensitiveConfigValue("password=123") {
		t.Fatal("expected sensitive config detection")
	}
	issues := sensitiveMetadataMapIssues("Pod", "prod", "api", map[string]string{"note": strings.Repeat("x", 300) + "." + strings.Repeat("y", 30) + "." + strings.Repeat("z", 30)}, "annotations")
	if len(issues) == 0 {
		t.Fatal("expected metadata issue for structured blob")
	}
}

func TestCheckConfigAndDataExposure(t *testing.T) {
	ctx := context.Background()
	pathType := networkingv1.PathTypePrefix
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/configmaps":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{Items: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "prod"}, Data: map[string]string{"password": "secret"}}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name:    "api",
					Args:    []string{"--debug"},
					Env:     []corev1.EnvVar{{Name: "API_KEY", Value: "secret"}},
					EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}},
				}}},
			}}})
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod", Labels: map[string]string{"app": "grafana"}}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{{Name: "metrics", Port: 9090}}}}}})
		case "/apis/networking.k8s.io/v1/namespaces/prod/ingresses":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.IngressList{Items: []networkingv1.Ingress{{
				ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: "prod"},
				Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
					Host: "grafana.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/metrics",
							PathType: &pathType,
							Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "grafana"}},
						}}},
					},
				}}},
			}}})
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Annotations: map[string]string{"token": "secret"}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckConfigAndDataExposure(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckConfigAndDataExposure returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several exposure issues, got %+v", issues)
	}
	if _, err := CheckConfigAndDataExposure(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
