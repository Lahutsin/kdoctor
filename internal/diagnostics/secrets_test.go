package diagnostics

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func weakRSACertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSecretHelpersAndCheckSecrets(t *testing.T) {
	now := time.Now()
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: "secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "app-secret"}}}, {Name: "projected", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "app-secret"}}}}}}}},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull-secret"}},
			Containers: []corev1.Container{{Name: "api", Env: []corev1.EnvVar{{Name: "PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "app-secret"}}}}}, EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "env-secret"}}}}}},
		},
	}
	usage := collectSecretUsage([]corev1.Pod{pod}, []networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "prod"}, Spec: networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "tls-secret"}}}}}, []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "builder", Namespace: "prod"}, ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull-secret"}}}})
	if usage["prod/app-secret"].count < 3 || usage["prod/pull-secret"].count != 2 {
		t.Fatal("expected secret usage collection")
	}
	oldSecret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "db-secret", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-400 * 24 * time.Hour))}}
	if len(secretAgeAndRotationIssues(oldSecret, namespaceMeta{name: "prod"})) == 0 || len(unusedSecretIssues(corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "prod"}, Type: corev1.SecretTypeTLS}, nil)) == 0 {
		t.Fatal("expected age and unused secret issues")
	}
	spread := &secretUsage{pods: make([]string, 10), envPods: []string{"Pod/prod/api"}}
	if len(secretSpreadIssues(corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: "prod"}}, spread)) < 2 {
		t.Fatal("expected secret spread issues")
	}
	weakTLS := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "prod"}, Data: map[string][]byte{"tls.crt": weakRSACertPEM(t, "tls.prod.svc")}}
	if len(tlsSecretCryptoIssues(weakTLS)) == 0 || weakCertificateFinding(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}, SignatureAlgorithm: x509.SHA1WithRSA}) == "" {
		t.Fatal("expected TLS crypto weakness detection")
	}
	dockerSecret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-200 * 24 * time.Hour))}, Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"registry.example.com":{"auth":"abcd"}}}`)}}
	if len(dockerRegistrySecretIssues(dockerSecret)) < 2 || !hasStaticDockerAuth(dockerSecret.Data) {
		t.Fatal("expected docker registry secret issues")
	}
	cloudSecret := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cloud", Namespace: "prod"}, Data: map[string][]byte{"aws_secret_access_key": []byte("secret"), "gcp.json": []byte(`{"type": "service_account"}`), "azure": []byte("clientSecret=foo")}}
	if len(cloudCredentialSecretIssues(cloudSecret)) == 0 || len(detectCloudCredentials(cloudSecret)) < 3 {
		t.Fatal("expected cloud credential detection")
	}
	if !shouldIgnoreSecretForRotation(corev1.Secret{Type: corev1.SecretTypeServiceAccountToken}) || !shouldIgnoreUnusedSecret(corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "default-token-abc"}}) {
		t.Fatal("expected secret ignore helpers")
	}
	if rotationMetadata(map[string]string{"last-rotated": "yesterday"}) == "" || !looksSensitiveConfigKey("API_KEY") || !looksSensitiveConfigValue("password=secret") || !isWeakSignatureAlgorithm(x509.MD5WithRSA) {
		t.Fatal("unexpected secret helper behavior")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{oldSecret, weakTLS, dockerSecret, cloudSecret}})
		case "/api/v1/namespaces/prod/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "builder", Namespace: "prod"}, ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull-secret"}}}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/apis/networking.k8s.io/v1/namespaces/prod/ingresses":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.IngressList{Items: []networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "prod"}, Spec: networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "tls-secret"}}}}}})
		case "/api/v1/namespaces/kube-system/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "kube-apiserver", Command: []string{"kube-apiserver"}}}}}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err := CheckSecrets(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckSecrets returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected secret issues, got %+v", issues)
	}
	if _, err := CheckSecrets(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
	_ = appsv1.Deployment{}
}