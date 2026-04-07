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

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func generateSelfSignedCertPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateCAAndLeafPEM(t *testing.T, caCN, leafCN string, leafNotAfter time.Time) ([]byte, []byte) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caTpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	return leafPEM, caPEM
}

func TestCertificateHelpers(t *testing.T) {
	bundle := append(generateSelfSignedCertPEM(t, "critical", time.Now().Add(2*24*time.Hour)), []byte("not-a-cert")...)
	certs := parsePEMCertificates(bundle)
	if len(certs) != 1 {
		t.Fatalf("expected 1 parsed cert, got %d", len(certs))
	}

	issues := evaluateCertificateBundle("prod", "web-tls", "TLSSecret", bundle, "tls-secret")
	if len(issues) != 1 || issues[0].Severity != SeverityCritical {
		t.Fatalf("unexpected certificate issues: %+v", issues)
	}

	warningIssues := evaluateCertificateBundle("prod", "web-tls", "TLSSecret", generateSelfSignedCertPEM(t, "warning", time.Now().Add(10*24*time.Hour)), "tls-secret")
	if len(warningIssues) != 1 || warningIssues[0].Severity != SeverityWarning {
		t.Fatalf("unexpected warning issues: %+v", warningIssues)
	}

	if humanDuration(-time.Minute) != "expired" || humanDuration(90*time.Minute) != "1h" || humanDuration(48*time.Hour) != "2d" {
		t.Fatal("unexpected humanDuration output")
	}
}

func TestCheckCertificates(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: "prod"},
				Data:       map[string][]byte{"tls.crt": generateSelfSignedCertPEM(t, "web", time.Now().Add(2*24*time.Hour))},
			}}})
		case "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
			writeJSONResponse(t, w, http.StatusOK, &admissionv1.ValidatingWebhookConfigurationList{Items: []admissionv1.ValidatingWebhookConfiguration{{
				ObjectMeta: metav1.ObjectMeta{Name: "admission"},
				Webhooks:   []admissionv1.ValidatingWebhook{{Name: "validate.prod", ClientConfig: admissionv1.WebhookClientConfig{CABundle: generateSelfSignedCertPEM(t, "ca", time.Now().Add(20*24*time.Hour))}}},
			}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckCertificates(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckCertificates returned error: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 certificate issues, got %+v", issues)
	}
}
