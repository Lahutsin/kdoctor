package diagnostics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckCertificates(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var issues []Issue

	secrets, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets.Items {
		crt := secret.Data["tls.crt"]
		if len(crt) == 0 {
			continue
		}
		issues = append(issues, evaluateCertificateBundle(secret.Namespace, secret.Name, "TLSSecret", crt, "tls-secret")...)
	}

	vcfgs, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cfg := range vcfgs.Items {
			for _, wh := range cfg.Webhooks {
				if len(wh.ClientConfig.CABundle) == 0 {
					continue
				}
				issues = append(issues, evaluateCertificateBundle("", fmt.Sprintf("%s/%s", cfg.Name, wh.Name), "Certificate", wh.ClientConfig.CABundle, "webhook-ca")...)
			}
		}
	}

	return issues, nil
}

func evaluateCertificateBundle(namespace, name, kind string, pemData []byte, check string) []Issue {
	certs := parsePEMCertificates(pemData)
	issues := make([]Issue, 0)
	now := time.Now()
	for _, cert := range certs {
		remaining := time.Until(cert.NotAfter)
		var severity Severity
		switch {
		case remaining <= 0:
			severity = SeverityCritical
		case remaining <= 7*24*time.Hour:
			severity = SeverityCritical
		case remaining <= 30*24*time.Hour:
			severity = SeverityWarning
		default:
			continue
		}
		issues = append(issues, Issue{
			Kind:           kind,
			Namespace:      namespace,
			Name:           name,
			Severity:       severity,
			Category:       "security",
			Check:          check,
			Summary:        fmt.Sprintf("certificate expires in %s (CN=%s, notAfter=%s)", humanDuration(remaining), cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339)),
			Recommendation: "Rotate the certificate before it expires and verify the issuer/renewal automation.",
			References:     []string{fmt.Sprintf("observedAt=%s", now.Format(time.RFC3339))},
		})
	}
	return issues
}

func parsePEMCertificates(pemData []byte) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0)
	for len(pemData) > 0 {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		pemData = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	days := int(d.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
