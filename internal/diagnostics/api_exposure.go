package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func CheckAPIExposure(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	if cs == nil {
		return nil
	}
	issues := make([]Issue, 0)
	endpoint, endpointSource := detectAPIEndpoint(ctx, cs)
	provider := detectClusterProvider(ctx, cs)
	if endpoint != "" {
		if public, host := isPublicAPIEndpoint(endpoint); public {
			issues = append(issues, Issue{
				Kind:           "APIServer",
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "apiserver-public-endpoint",
				Summary:        fmt.Sprintf("apiserver endpoint appears public: %s", host),
				Recommendation: "Verify the API endpoint is protected by CIDR allowlists or equivalent edge restrictions if public access is required.",
				References:     []string{fmt.Sprintf("source=%s", endpointSource)},
			})
			if provider != "" {
				issues = append(issues, Issue{
					Kind:           "APIServer",
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "managed-cluster-public-endpoint",
					Summary:        fmt.Sprintf("managed cluster provider %s exposes a public API endpoint", provider),
					Recommendation: "Confirm private API access is also enabled where the platform supports it, and avoid relying solely on the public endpoint.",
				})
				issues = append(issues, Issue{
					Kind:           "APIServer",
					Severity:       SeverityInfo,
					Category:       "security",
					Check:          "apiserver-perimeter-unverified",
					Summary:        fmt.Sprintf("security groups/firewall/NACL restrictions for provider %s cannot be verified from the Kubernetes API", provider),
					Recommendation: "Review the cloud-side API endpoint perimeter manually to ensure source networks are tightly restricted.",
				})
			}
		}
	}

	issues = append(issues, inspectKubeconfigsInCluster(ctx, cs)...)

	return issues
}

func detectAPIEndpoint(ctx context.Context, cs *kubernetes.Clientset) (string, string) {
	clusterInfo, err := cs.CoreV1().ConfigMaps("kube-public").Get(ctx, "cluster-info", metav1.GetOptions{})
	if err == nil {
		for _, key := range []string{"kubeconfig", "config"} {
			if raw := clusterInfo.Data[key]; raw != "" {
				cfg, loadErr := clientcmd.Load([]byte(raw))
				if loadErr == nil {
					for _, cluster := range cfg.Clusters {
						if cluster.Server != "" {
							return cluster.Server, fmt.Sprintf("configmap/kube-public/cluster-info:%s", key)
						}
					}
				}
			}
		}
	}
	service, err := cs.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err == nil && service.Spec.ClusterIP != "" {
		return "https://" + net.JoinHostPort(service.Spec.ClusterIP, "443"), "service/default/kubernetes"
	}
	return "", ""
}

func isPublicAPIEndpoint(raw string) (bool, string) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false, ""
	}
	host := parsed.Hostname()
	if host == "" {
		return false, ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast(), host
	}
	hostLower := strings.ToLower(host)
	for _, suffix := range []string{".internal", ".cluster.local", ".svc", ".local"} {
		if strings.HasSuffix(hostLower, suffix) {
			return false, host
		}
	}
	return true, host
}

func detectClusterProvider(ctx context.Context, cs *kubernetes.Clientset) string {
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 10})
	if err != nil {
		return ""
	}
	providers := map[string]int{}
	for _, node := range nodes.Items {
		providerID := strings.ToLower(node.Spec.ProviderID)
		switch {
		case strings.HasPrefix(providerID, "aws://"):
			providers["eks/aws"]++
		case strings.HasPrefix(providerID, "gce://"):
			providers["gke/gce"]++
		case strings.HasPrefix(providerID, "azure://"):
			providers["aks/azure"]++
		case strings.HasPrefix(providerID, "openstack://"):
			providers["openstack"]++
		case strings.HasPrefix(providerID, "vsphere://"):
			providers["vsphere"]++
		}
	}
	if len(providers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(providers))
	for key := range providers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys[0]
}

func inspectKubeconfigsInCluster(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	issues := make([]Issue, 0)
	secrets, err := cs.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, secret := range secrets.Items {
			issues = append(issues, inspectKubeconfigCarrier(secret.Namespace, secret.Name, secret.Data, "Secret")...)
		}
	}
	configMaps, err := cs.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, configMap := range configMaps.Items {
			data := map[string][]byte{}
			for key, value := range configMap.Data {
				data[key] = []byte(value)
			}
			issues = append(issues, inspectKubeconfigCarrier(configMap.Namespace, configMap.Name, data, "ConfigMap")...)
		}
	}
	return issues
}

func inspectKubeconfigCarrier(namespace, name string, data map[string][]byte, kind string) []Issue {
	issues := make([]Issue, 0)
	for key, value := range data {
		if !looksLikeKubeconfig(key, value) {
			continue
		}
		cfg, err := clientcmd.Load(value)
		if err != nil {
			continue
		}
		for authName, authInfo := range cfg.AuthInfos {
			severity := SeverityWarning
			summary := fmt.Sprintf("%s %s/%s contains kubeconfig auth info %s", strings.ToLower(kind), namespace, name, authName)
			recommendation := "Store only short-lived or federated identities in-cluster; avoid static kubeconfig credentials in secrets or CI artifacts."
			check := "kubeconfig-credential"
			if authInfo.Username != "" || authInfo.Password != "" {
				severity = SeverityCritical
				check = "kubeconfig-basic-auth"
				summary = fmt.Sprintf("%s %s/%s contains basic-auth style kubeconfig credentials", strings.ToLower(kind), namespace, name)
			}
			if authInfo.Token != "" || authInfo.TokenFile != "" {
				check = "kubeconfig-static-token"
			}
			if len(authInfo.ClientKeyData) > 0 || authInfo.ClientKey != "" {
				check = "kubeconfig-client-cert"
			}
			if looksPrivilegedAuthName(authName, cfg.Contexts) {
				severity = SeverityCritical
				summary = fmt.Sprintf("%s %s/%s appears to contain high-privilege kubeconfig credentials (%s)", strings.ToLower(kind), namespace, name, authName)
				recommendation = "Remove cluster-admin style kubeconfigs from in-cluster storage and switch CI or automation to least-privilege, short-lived identities."
			}
			if authInfo.Exec != nil || authInfo.AuthProvider != nil {
				continue
			}
			issues = append(issues, Issue{
				Kind:           kind,
				Namespace:      namespace,
				Name:           name,
				Severity:       severity,
				Category:       "security",
				Check:          check,
				Summary:        summary,
				Recommendation: recommendation,
				References:     []string{fmt.Sprintf("key=%s", key)},
			})
		}
	}
	return issues
}

func inspectLongLivedTokens(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	issues := make([]Issue, 0)
	secrets, err := cs.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	for _, secret := range secrets.Items {
		if secret.Type != corev1.SecretTypeServiceAccountToken {
			continue
		}
		saName := secret.Annotations[corev1.ServiceAccountNameKey]
		issues = append(issues, Issue{
			Kind:           "Secret",
			Namespace:      secret.Namespace,
			Name:           secret.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "legacy-serviceaccount-token",
			Summary:        fmt.Sprintf("legacy long-lived service account token secret detected for service account %s", saName),
			Recommendation: "Prefer projected short-lived service account tokens or workload identity instead of static token secrets.",
		})
	}
	return issues
}

func looksLikeKubeconfig(key string, value []byte) bool {
	keyLower := strings.ToLower(key)
	if strings.Contains(keyLower, "kubeconfig") || keyLower == "config" {
		return true
	}
	text := strings.ToLower(string(value))
	return strings.Contains(text, "apiVersion: v1") && strings.Contains(text, "clusters:") && strings.Contains(text, "users:")
}

func looksPrivilegedAuthName(authName string, contexts map[string]*clientcmdapi.Context) bool {
	name := strings.ToLower(authName)
	if strings.Contains(name, "admin") || strings.Contains(name, "cluster-admin") || strings.Contains(name, "system:masters") || strings.Contains(name, "system:admin") {
		return true
	}
	for _, ctx := range contexts {
		if ctx != nil && ctx.AuthInfo == authName {
			ctxName := strings.ToLower(ctx.Cluster + "/" + ctx.Namespace + "/" + ctx.AuthInfo)
			if strings.Contains(ctxName, "admin") || strings.Contains(ctxName, "cluster-admin") || strings.Contains(ctxName, "system:masters") || strings.Contains(ctxName, "system:admin") {
				return true
			}
		}
	}
	return false
}
