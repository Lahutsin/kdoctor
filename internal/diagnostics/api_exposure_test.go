package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestAPIExposureHelpers(t *testing.T) {
	if public, host := isPublicAPIEndpoint("https://35.1.2.3:6443"); !public || host != "35.1.2.3" {
		t.Fatalf("expected public endpoint detection, got public=%v host=%q", public, host)
	}
	if public, _ := isPublicAPIEndpoint("https://kubernetes.default.svc"); public {
		t.Fatal("expected cluster-local endpoint to be private")
	}
	if !looksLikeKubeconfig("config", []byte("apiVersion: v1\nclusters:\nusers:\n")) {
		t.Fatal("expected kubeconfig detection")
	}
	if !(looksPrivilegedAuthName("cluster-admin", map[string]*clientcmdapi.Context{"ctx": {Cluster: "prod", AuthInfo: "cluster-admin"}})) {
		t.Fatal("expected privileged auth name to be detected")
	}
	issues := inspectKubeconfigCarrier("prod", "ci-config", map[string][]byte{"kubeconfig": kubeconfigBytes(t, "https://35.1.2.3:6443", "cluster-admin", true)}, "Secret")
	if len(issues) != 1 || issues[0].Severity != SeverityCritical || issues[0].Check != "kubeconfig-basic-auth" {
		t.Fatalf("unexpected kubeconfig carrier issues: %+v", issues)
	}
}

func TestCheckAPIExposureAndEndpointDetection(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-public/configmaps/cluster-info":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"}, Data: map[string]string{"kubeconfig": string(kubeconfigBytes(t, "https://35.1.2.3:6443", "reader", false))}})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-123"}}}})
		case "/api/v1/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "ci-kubeconfig", Namespace: "prod"}, Data: map[string][]byte{"kubeconfig": kubeconfigBytes(t, "https://35.1.2.3:6443", "reader", false)}}}})
		case "/api/v1/configmaps":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	endpoint, source := detectAPIEndpoint(ctx, cs)
	if endpoint != "https://35.1.2.3:6443" || !strings.Contains(source, "cluster-info") {
		t.Fatalf("unexpected endpoint detection: endpoint=%q source=%q", endpoint, source)
	}
	if provider := detectClusterProvider(ctx, cs); provider != "eks/aws" {
		t.Fatalf("unexpected provider: %q", provider)
	}
	issues := CheckAPIExposure(ctx, cs)
	if len(issues) < 4 {
		t.Fatalf("expected multiple exposure issues, got %+v", issues)
	}
	checks := map[string]bool{}
	for _, issue := range issues {
		checks[issue.Check] = true
	}
	for _, check := range []string{"apiserver-public-endpoint", "managed-cluster-public-endpoint", "apiserver-perimeter-unverified", "kubeconfig-static-token"} {
		if !checks[check] {
			t.Fatalf("expected check %q in issues %+v", check, issues)
		}
	}
}

func TestAPIExposureFallbackAndLongLivedTokens(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-public/configmaps/cluster-info":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		case "/api/v1/namespaces/default/services/kubernetes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.1"}})
		case "/api/v1/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "legacy-token", Namespace: "prod", Annotations: map[string]string{corev1.ServiceAccountNameKey: "default"}}, Type: corev1.SecretTypeServiceAccountToken}}})
		case "/api/v1/configmaps", "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	endpoint, source := detectAPIEndpoint(ctx, cs)
	if endpoint != "https://10.0.0.1:443" || source != "service/default/kubernetes" {
		t.Fatalf("unexpected fallback endpoint: endpoint=%q source=%q", endpoint, source)
	}
	tokenIssues := inspectLongLivedTokens(ctx, cs)
	if len(tokenIssues) != 1 || tokenIssues[0].Check != "legacy-serviceaccount-token" {
		t.Fatalf("unexpected token issues: %+v", tokenIssues)
	}
}
