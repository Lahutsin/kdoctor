package diagnostics

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type secretUsage struct {
	references []string
	pods       []string
	envPods    []string
	mountPods  []string
	count      int
}

func CheckSecrets(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}
	secrets, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	serviceAccounts, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		ingresses = &networkingv1.IngressList{}
	}

	issues := make([]Issue, 0)
	issues = append(issues, checkSecretEncryptionAtRest(ctx, cs)...)
	usage := collectSecretUsage(pods.Items, ingresses.Items, serviceAccounts.Items)

	for _, secret := range secrets.Items {
		nsMeta := namespaces[secret.Namespace]
		usageEntry := usage[secret.Namespace+"/"+secret.Name]
		issues = append(issues, secretAgeAndRotationIssues(secret, nsMeta)...)
		issues = append(issues, unusedSecretIssues(secret, usageEntry)...)
		issues = append(issues, secretSpreadIssues(secret, usageEntry)...)
		issues = append(issues, tlsSecretCryptoIssues(secret)...)
		issues = append(issues, dockerRegistrySecretIssues(secret)...)
		issues = append(issues, cloudCredentialSecretIssues(secret)...)
	}

	return dedupeIssues(issues), nil
}

func checkSecretEncryptionAtRest(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	components, err := discoverControlPlaneComponents(ctx, cs)
	if err != nil {
		return nil
	}
	pod := firstComponentPod(components["kube-apiserver"])
	if pod == nil {
		return nil
	}
	flags := collectContainerFlags(*pod)
	if firstFlagValue(flags, "encryption-provider-config") != "" {
		return nil
	}
	return []Issue{{
		Kind:           "Secret",
		Namespace:      metav1.NamespaceSystem,
		Name:           pod.Name,
		Severity:       SeverityCritical,
		Category:       "security",
		Check:          "secret-encryption-at-rest",
		Summary:        "secrets do not appear to be encrypted at rest because kube-apiserver lacks --encryption-provider-config",
		Recommendation: "Enable etcd encryption for secrets with --encryption-provider-config and rotate existing secrets after the provider is configured.",
	}}
}

func collectSecretUsage(pods []corev1.Pod, ingresses []networkingv1.Ingress, serviceAccounts []corev1.ServiceAccount) map[string]*secretUsage {
	usage := map[string]*secretUsage{}
	get := func(namespace, name string) *secretUsage {
		key := namespace + "/" + name
		entry := usage[key]
		if entry == nil {
			entry = &secretUsage{}
			usage[key] = entry
		}
		return entry
	}

	for _, pod := range pods {
		podRef := "Pod/" + pod.Namespace + "/" + pod.Name
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil && volume.Secret.SecretName != "" {
				entry := get(pod.Namespace, volume.Secret.SecretName)
				entry.references = append(entry.references, podRef+":volume")
				entry.pods = append(entry.pods, podRef)
				entry.mountPods = append(entry.mountPods, podRef)
				entry.count++
			}
			if volume.Projected == nil {
				continue
			}
			for _, source := range volume.Projected.Sources {
				if source.Secret == nil || source.Secret.Name == "" {
					continue
				}
				entry := get(pod.Namespace, source.Secret.Name)
				entry.references = append(entry.references, podRef+":projected-volume")
				entry.pods = append(entry.pods, podRef)
				entry.mountPods = append(entry.mountPods, podRef)
				entry.count++
			}
		}
		for _, secretRef := range pod.Spec.ImagePullSecrets {
			if secretRef.Name == "" {
				continue
			}
			entry := get(pod.Namespace, secretRef.Name)
			entry.references = append(entry.references, podRef+":imagePullSecret")
			entry.pods = append(entry.pods, podRef)
			entry.count++
		}
		for _, container := range pod.Spec.InitContainers {
			collectContainerSecretRefs(get, pod.Namespace, podRef, container)
		}
		for _, container := range pod.Spec.Containers {
			collectContainerSecretRefs(get, pod.Namespace, podRef, container)
		}
	}

	for _, ingress := range ingresses {
		for _, tlsEntry := range ingress.Spec.TLS {
			if tlsEntry.SecretName == "" {
				continue
			}
			entry := get(ingress.Namespace, tlsEntry.SecretName)
			entry.references = append(entry.references, "Ingress/"+ingress.Namespace+"/"+ingress.Name+":tls")
			entry.count++
		}
	}

	for _, sa := range serviceAccounts {
		saRef := "ServiceAccount/" + sa.Namespace + "/" + sa.Name
		for _, secretRef := range sa.ImagePullSecrets {
			if secretRef.Name == "" {
				continue
			}
			entry := get(sa.Namespace, secretRef.Name)
			entry.references = append(entry.references, saRef+":imagePullSecret")
			entry.count++
		}
	}

	for key, entry := range usage {
		_ = key
		entry.references = uniqueStrings(entry.references)
		entry.pods = uniqueStrings(entry.pods)
		entry.envPods = uniqueStrings(entry.envPods)
		entry.mountPods = uniqueStrings(entry.mountPods)
	}
	return usage
}

func collectContainerSecretRefs(get func(namespace, name string) *secretUsage, namespace, podRef string, container corev1.Container) {
	for _, env := range container.Env {
		if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil || env.ValueFrom.SecretKeyRef.Name == "" {
			continue
		}
		entry := get(namespace, env.ValueFrom.SecretKeyRef.Name)
		entry.references = append(entry.references, podRef+":env:"+container.Name)
		entry.pods = append(entry.pods, podRef)
		entry.envPods = append(entry.envPods, podRef)
		entry.count++
	}
	for _, envFrom := range container.EnvFrom {
		if envFrom.SecretRef == nil || envFrom.SecretRef.Name == "" {
			continue
		}
		entry := get(namespace, envFrom.SecretRef.Name)
		entry.references = append(entry.references, podRef+":envFrom:"+container.Name)
		entry.pods = append(entry.pods, podRef)
		entry.envPods = append(entry.envPods, podRef)
		entry.count++
	}
}

func secretAgeAndRotationIssues(secret corev1.Secret, ns namespaceMeta) []Issue {
	if shouldIgnoreSecretForRotation(secret) {
		return nil
	}
	age := time.Since(secret.CreationTimestamp.Time)
	rotationMarker := rotationMetadata(secret.Annotations)
	issues := make([]Issue, 0)
	if age > 180*24*time.Hour && rotationMarker == "" {
		severity := SeverityInfo
		if age > 365*24*time.Hour || isProductionNamespace(ns) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "secret-rotation-cadence",
			Summary:        fmt.Sprintf("secret is %s old and does not advertise a rotation marker", humanDuration(age)),
			Recommendation: "Define a rotation cadence for long-lived secrets and record last-rotated metadata or hand the secret over to a managed rotation mechanism.",
		})
	}
	return issues
}

func unusedSecretIssues(secret corev1.Secret, usage *secretUsage) []Issue {
	if usage != nil && usage.count > 0 {
		return nil
	}
	if shouldIgnoreUnusedSecret(secret) {
		return nil
	}
	severity := SeverityInfo
	if secret.Type == corev1.SecretTypeTLS || secret.Type == corev1.SecretTypeDockerConfigJson || secret.Type == corev1.SecretTypeDockercfg {
		severity = SeverityWarning
	}
	return []Issue{{
		Kind:           "Secret",
		Namespace:      secret.Namespace,
		Name:           secret.Name,
		Severity:       severity,
		Category:       "security",
		Check:          "secret-unused",
		Summary:        "secret does not appear to be referenced by pods or ingress resources",
		Recommendation: "Delete unused secrets or document why they must remain present to reduce credential sprawl and stale secret risk.",
	}}
}

func secretSpreadIssues(secret corev1.Secret, usage *secretUsage) []Issue {
	if usage == nil {
		return nil
	}
	issues := make([]Issue, 0)
	if len(usage.pods) >= 10 {
		severity := SeverityWarning
		if len(usage.pods) >= 25 {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "secret-fanout",
			Summary:        fmt.Sprintf("secret is referenced by many pods (%d)", len(usage.pods)),
			Recommendation: "Reduce blast radius by scoping secrets to fewer workloads or splitting them by application and environment.",
			References:     usage.pods,
		})
	}
	if len(usage.envPods) > 0 {
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "secret-env-vars",
			Summary:        fmt.Sprintf("secret is exposed through environment variables in %d pod(s)", len(usage.envPods)),
			Recommendation: "Prefer secret volume mounts over environment variables so values are not trivially exposed in process environments and pod specs.",
			References:     usage.envPods,
		})
	}
	return issues
}

func tlsSecretCryptoIssues(secret corev1.Secret) []Issue {
	crt := secret.Data["tls.crt"]
	if len(crt) == 0 {
		return nil
	}
	issues := make([]Issue, 0)
	for _, cert := range parsePEMCertificates(crt) {
		if finding := weakCertificateFinding(cert); finding != "" {
			issues = append(issues, Issue{
				Kind:           "Secret",
				Namespace:      secret.Namespace,
				Name:           secret.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "tls-weak-crypto",
				Summary:        finding,
				Recommendation: "Reissue the certificate with modern key sizes and a current signature algorithm, then roll it out before the next renewal window.",
			})
		}
	}
	return issues
}

func weakCertificateFinding(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		return fmt.Sprintf("certificate uses weak signature algorithm %s (CN=%s)", cert.SignatureAlgorithm.String(), cert.Subject.CommonName)
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Sprintf("certificate uses weak RSA key size %d bits (CN=%s)", key.N.BitLen(), cert.Subject.CommonName)
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Params().BitSize < 256 {
			return fmt.Sprintf("certificate uses weak ECDSA key size %d bits (CN=%s)", key.Params().BitSize, cert.Subject.CommonName)
		}
	case *dsa.PublicKey:
		return fmt.Sprintf("certificate uses legacy DSA public key (CN=%s)", cert.Subject.CommonName)
	case ed25519.PublicKey:
		return ""
	default:
		if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			return fmt.Sprintf("certificate uses unknown public key algorithm (CN=%s)", cert.Subject.CommonName)
		}
	}
	return ""
}

func dockerRegistrySecretIssues(secret corev1.Secret) []Issue {
	if secret.Type != corev1.SecretTypeDockerConfigJson && secret.Type != corev1.SecretTypeDockercfg {
		return nil
	}
	age := time.Since(secret.CreationTimestamp.Time)
	issues := make([]Issue, 0)
	if age > 90*24*time.Hour {
		severity := SeverityInfo
		if age > 180*24*time.Hour {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "docker-registry-secret-age",
			Summary:        fmt.Sprintf("docker registry secret is %s old", humanDuration(age)),
			Recommendation: "Rotate long-lived registry credentials or switch to short-lived registry tokens if your platform supports them.",
		})
	}
	if hasStaticDockerAuth(secret.Data) {
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "docker-registry-static-auth",
			Summary:        "docker registry secret appears to store static auth credentials",
			Recommendation: "Prefer short-lived registry tokens or workload identity integrations over static docker auth blobs when possible.",
		})
	}
	return issues
}

func cloudCredentialSecretIssues(secret corev1.Secret) []Issue {
	findings := detectCloudCredentials(secret)
	if len(findings) == 0 {
		return nil
	}
	severity := SeverityCritical
	if rotationMetadata(secret.Annotations) != "" {
		severity = SeverityWarning
	}
	return []Issue{{
		Kind:           "Secret",
		Namespace:      secret.Namespace,
		Name:           secret.Name,
		Severity:       severity,
		Category:       "security",
		Check:          "cloud-credentials-secret",
		Summary:        fmt.Sprintf("plain secret appears to contain cloud credentials: %s", strings.Join(findings, ", ")),
		Recommendation: "Move cloud credentials to workload identity or a managed secret backend, and ensure a documented rotation policy exists for any credential that must remain in-cluster.",
	}}
}

func shouldIgnoreSecretForRotation(secret corev1.Secret) bool {
	if shouldIgnoreUnusedSecret(secret) {
		return true
	}
	if secret.Type == corev1.SecretTypeServiceAccountToken {
		return true
	}
	return false
}

func shouldIgnoreUnusedSecret(secret corev1.Secret) bool {
	name := strings.ToLower(secret.Name)
	if strings.HasPrefix(name, "default-token-") || strings.Contains(name, "helm") || strings.Contains(name, "leader-election") {
		return true
	}
	for _, key := range []string{"service-account.name", "kubernetes.io/service-account.name"} {
		if secret.Annotations[key] != "" {
			return true
		}
	}
	return secret.Type == corev1.SecretTypeServiceAccountToken
}

func rotationMetadata(annotations map[string]string) string {
	for key, value := range annotations {
		keyLower := strings.ToLower(key)
		for _, marker := range []string{"rotated", "rotation", "last-rotated", "reloader", "cert-manager.io/renewal-time", "managed-by", "external-secrets"} {
			if strings.Contains(keyLower, marker) && value != "" {
				return value
			}
		}
	}
	return ""
}

func looksSensitiveConfigKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "privatekey", "private_key", "client_secret", "aws_access_key_id", "aws_secret_access_key", "connectionstring", "connection_string"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func looksSensitiveConfigValue(value string) bool {
	text := strings.TrimSpace(value)
	if text == "" {
		return false
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "-----begin private key-----") || strings.Contains(lower, "aws_secret_access_key") || strings.Contains(lower, "azure_client_secret") {
		return true
	}
	for _, marker := range []string{"api_key", "client_secret", "password=", "passwd=", "token="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if strings.Contains(text, "AKIA") || strings.Contains(text, "ASIA") {
		return true
	}
	return false
}

func hasStaticDockerAuth(data map[string][]byte) bool {
	for _, key := range []string{corev1.DockerConfigJsonKey, corev1.DockerConfigKey} {
		blob := data[key]
		if len(blob) == 0 {
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal(blob, &cfg); err != nil {
			continue
		}
		if auths, ok := cfg["auths"].(map[string]any); ok && len(auths) > 0 {
			return true
		}
	}
	return false
}

func detectCloudCredentials(secret corev1.Secret) []string {
	findings := make([]string, 0)
	for key, value := range secret.Data {
		keyLower := strings.ToLower(key)
		text := strings.ToLower(string(value))
		switch {
		case strings.Contains(keyLower, "aws_access_key") || strings.Contains(keyLower, "aws_secret_access_key") || strings.Contains(text, "aws_secret_access_key"):
			findings = append(findings, "aws")
		case strings.Contains(keyLower, "gcp") || strings.Contains(keyLower, "google") || strings.Contains(text, "type\": \"service_account\""):
			findings = append(findings, "gcp")
		case strings.Contains(keyLower, "azure") || strings.Contains(text, "clientsecret") || strings.Contains(text, "tenantid"):
			findings = append(findings, "azure")
		case strings.Contains(keyLower, "digitalocean") || strings.Contains(keyLower, "do_token"):
			findings = append(findings, "digitalocean")
		case strings.Contains(keyLower, "openstack") || strings.Contains(text, "auth_url"):
			findings = append(findings, "openstack")
		}
	}
	return uniqueStrings(findings)
}

func isWeakSignatureAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}
