package diagnostics

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type namespaceMeta struct {
	name        string
	labels      map[string]string
	annotations map[string]string
}

func CheckServiceAccountsAndTokens(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
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
	serviceAccounts, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	provider := detectClusterProvider(ctx, cs)
	roleIndex, err := buildRoleIndex(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	saRules, saSources, crossNamespaceSecretIssues, err := buildServiceAccountRBACView(ctx, cs, ns, roleIndex)
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	issues = append(issues, crossNamespaceSecretIssues...)
	issues = append(issues, inspectLongLivedTokens(ctx, cs)...)
	issues = append(issues, serviceAccountAutomountIssues(serviceAccounts.Items, pods.Items, namespaces, saRules)...)
	issues = append(issues, defaultServiceAccountUsageIssues(pods.Items, namespaces)...)
	issues = append(issues, projectedTokenLifetimeIssues(pods.Items)...)
	issues = append(issues, unnecessaryTokenMountIssues(pods.Items, serviceAccounts.Items, namespaces, saRules, provider)...)
	issues = append(issues, workloadIdentityIssues(serviceAccounts.Items, pods.Items, provider, saSources)...)

	return dedupeIssues(issues), nil
}

func listNamespaceMeta(ctx context.Context, cs *kubernetes.Clientset, namespace string) (map[string]namespaceMeta, error) {
	result := make(map[string]namespaceMeta)
	if namespace != "" {
		ns, err := cs.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		result[ns.Name] = namespaceMeta{name: ns.Name, labels: ns.Labels, annotations: ns.Annotations}
		return result, nil
	}
	namespaces, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ns := range namespaces.Items {
		result[ns.Name] = namespaceMeta{name: ns.Name, labels: ns.Labels, annotations: ns.Annotations}
	}
	return result, nil
}

func buildRoleIndex(ctx context.Context, cs *kubernetes.Clientset, namespace string) (map[string]rbacRoleMeta, error) {
	clusterRoles, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	roles, err := cs.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	index := make(map[string]rbacRoleMeta, len(clusterRoles.Items)+len(roles.Items))
	for _, role := range clusterRoles.Items {
		index[roleKey("ClusterRole", "", role.Name)] = rbacRoleMeta{kind: "ClusterRole", name: role.Name, rules: role.Rules}
	}
	for _, role := range roles.Items {
		index[roleKey("Role", role.Namespace, role.Name)] = rbacRoleMeta{kind: "Role", namespace: role.Namespace, name: role.Name, rules: role.Rules}
	}
	return index, nil
}

func buildServiceAccountRBACView(ctx context.Context, cs *kubernetes.Clientset, namespace string, roleIndex map[string]rbacRoleMeta) (map[string][]rbacv1.PolicyRule, map[string][]string, []Issue, error) {
	clusterRoleBindings, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	roleBindings, err := cs.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, nil, err
	}

	saRules := map[string][]rbacv1.PolicyRule{}
	saSources := map[string][]string{}
	issues := make([]Issue, 0)

	for _, binding := range clusterRoleBindings.Items {
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, "", binding.RoleRef.Name)]
		if !ok {
			continue
		}
		for _, subject := range binding.Subjects {
			if !strings.EqualFold(subject.Kind, "ServiceAccount") {
				continue
			}
			saKey := serviceAccountKey(subject.Namespace, subject.Name)
			saRules[saKey] = append(saRules[saKey], meta.rules...)
			saSources[saKey] = append(saSources[saKey], "ClusterRoleBinding/"+binding.Name)
			if ruleAllowsSecretsRead(meta.rules) {
				issues = append(issues, Issue{
					Kind:           "ServiceAccount",
					Namespace:      subject.Namespace,
					Name:           subject.Name,
					Severity:       SeverityCritical,
					Category:       "security",
					Check:          "serviceaccount-cross-namespace-secrets",
					Summary:        fmt.Sprintf("service account can read secrets across namespaces via clusterrolebinding %s", binding.Name),
					Recommendation: "Replace cluster-wide secret read access with namespace-scoped bindings or external secret delivery where possible.",
					References:     []string{"ClusterRoleBinding/" + binding.Name},
				})
			}
		}
	}

	for _, binding := range roleBindings.Items {
		roleNS := binding.Namespace
		if strings.EqualFold(binding.RoleRef.Kind, "ClusterRole") {
			roleNS = ""
		}
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, roleNS, binding.RoleRef.Name)]
		if !ok {
			continue
		}
		for _, subject := range binding.Subjects {
			if !strings.EqualFold(subject.Kind, "ServiceAccount") {
				continue
			}
			subjectNamespace := subject.Namespace
			if subjectNamespace == "" {
				subjectNamespace = binding.Namespace
			}
			saKey := serviceAccountKey(subjectNamespace, subject.Name)
			saRules[saKey] = append(saRules[saKey], meta.rules...)
			saSources[saKey] = append(saSources[saKey], "RoleBinding/"+binding.Namespace+"/"+binding.Name)
			if subjectNamespace != binding.Namespace && ruleAllowsSecretsRead(meta.rules) {
				issues = append(issues, Issue{
					Kind:           "ServiceAccount",
					Namespace:      subjectNamespace,
					Name:           subject.Name,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "serviceaccount-cross-namespace-secrets",
					Summary:        fmt.Sprintf("service account can read secrets in namespace %s via rolebinding %s", binding.Namespace, binding.Name),
					Recommendation: "Avoid binding service accounts into other namespaces for secret access unless the cross-namespace trust boundary is explicitly intended.",
					References:     []string{"RoleBinding/" + binding.Namespace + "/" + binding.Name},
				})
			}
		}
	}

	for key := range saSources {
		saSources[key] = uniqueStrings(saSources[key])
	}
	return saRules, saSources, issues, nil
}

func serviceAccountAutomountIssues(serviceAccounts []corev1.ServiceAccount, pods []corev1.Pod, namespaces map[string]namespaceMeta, saRules map[string][]rbacv1.PolicyRule) []Issue {
	usage := serviceAccountUsage(pods)
	issues := make([]Issue, 0)
	for _, sa := range serviceAccounts {
		key := serviceAccountKey(sa.Namespace, sa.Name)
		if usage[key] == 0 && len(saRules[key]) == 0 {
			continue
		}
		if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			continue
		}
		severity := SeverityInfo
		summary := "service account inherits default token automount behavior"
		if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
			summary = "service account explicitly enables automountServiceAccountToken"
		}
		if isProductionNamespace(namespaces[sa.Namespace]) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      sa.Namespace,
			Name:           sa.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "serviceaccount-automount",
			Summary:        summary,
			Recommendation: "Set automountServiceAccountToken=false by default and enable it only for workloads that actually need Kubernetes or workload-identity tokens.",
		})
	}
	return issues
}

func defaultServiceAccountUsageIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if !isProductionNamespace(namespaces[pod.Namespace]) {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		if saName != "default" {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "default-serviceaccount-production",
			Summary:        "pod in a production namespace uses the default service account",
			Recommendation: "Create a dedicated service account for the workload and bind only the permissions it needs.",
		})
	}
	return issues
}

func projectedTokenLifetimeIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		for _, volume := range pod.Spec.Volumes {
			if volume.Projected == nil {
				continue
			}
			for _, source := range volume.Projected.Sources {
				if source.ServiceAccountToken == nil || source.ServiceAccountToken.ExpirationSeconds == nil {
					continue
				}
				expiration := *source.ServiceAccountToken.ExpirationSeconds
				if expiration <= 86400 {
					continue
				}
				severity := SeverityWarning
				if expiration > 604800 {
					severity = SeverityCritical
				}
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       severity,
					Category:       "security",
					Check:          "projected-serviceaccount-token-lifetime",
					Summary:        fmt.Sprintf("projected service account token has long expirationSeconds=%d", expiration),
					Recommendation: "Keep projected tokens short-lived, typically around one hour, unless the workload has a documented reason to require longer-lived tokens.",
				})
			}
		}
	}
	return issues
}

func unnecessaryTokenMountIssues(pods []corev1.Pod, serviceAccounts []corev1.ServiceAccount, namespaces map[string]namespaceMeta, saRules map[string][]rbacv1.PolicyRule, provider string) []Issue {
	issues := make([]Issue, 0)
	saIndex := make(map[string]corev1.ServiceAccount, len(serviceAccounts))
	for _, sa := range serviceAccounts {
		saIndex[serviceAccountKey(sa.Namespace, sa.Name)] = sa
	}
	for _, pod := range pods {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		sa := saIndex[serviceAccountKey(pod.Namespace, saName)]
		if !podUsesServiceAccountToken(pod, sa) {
			continue
		}
		if podHasProjectedToken(pod) || podHasWorkloadIdentityIndicators(pod, sa, provider) {
			continue
		}
		if len(saRules[serviceAccountKey(pod.Namespace, saName)]) > 0 {
			continue
		}
		if podLooksLikeKubernetesClient(pod) {
			continue
		}
		severity := SeverityInfo
		if isProductionNamespace(namespaces[pod.Namespace]) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "unnecessary-serviceaccount-token",
			Summary:        "pod receives a service account token but does not appear to need one",
			Recommendation: "Disable automountServiceAccountToken for this workload or move it to a dedicated service account only if Kubernetes API access is actually required.",
		})
	}
	return issues
}

func workloadIdentityIssues(serviceAccounts []corev1.ServiceAccount, pods []corev1.Pod, provider string, saSources map[string][]string) []Issue {
	issues := make([]Issue, 0)
	podsBySA := make(map[string][]corev1.Pod)
	for _, pod := range pods {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		key := serviceAccountKey(pod.Namespace, saName)
		podsBySA[key] = append(podsBySA[key], pod)
	}

	for _, sa := range serviceAccounts {
		key := serviceAccountKey(sa.Namespace, sa.Name)
		awsRole := sa.Annotations["eks.amazonaws.com/role-arn"]
		gsa := sa.Annotations["iam.gke.io/gcp-service-account"]
		azureClientID := sa.Annotations["azure.workload.identity/client-id"]
		azureTenantID := sa.Annotations["azure.workload.identity/tenant-id"]

		if awsRole != "" {
			if !looksLikeAWSRoleARN(awsRole) {
				issues = append(issues, Issue{
					Kind:           "ServiceAccount",
					Namespace:      sa.Namespace,
					Name:           sa.Name,
					Severity:       SeverityCritical,
					Category:       "security",
					Check:          "workload-identity-irsa",
					Summary:        fmt.Sprintf("IRSA role annotation looks malformed: %s", awsRole),
					Recommendation: "Set eks.amazonaws.com/role-arn to a valid IAM role ARN and verify trust policy matches the cluster OIDC provider.",
				})
			}
			for _, pod := range podsBySA[key] {
				if !podHasEnv(pod, "AWS_ROLE_ARN") || !podHasEnv(pod, "AWS_WEB_IDENTITY_TOKEN_FILE") {
					issues = append(issues, Issue{
						Kind:           "Pod",
						Namespace:      pod.Namespace,
						Name:           pod.Name,
						Severity:       SeverityWarning,
						Category:       "security",
						Check:          "workload-identity-irsa",
						Summary:        "pod uses a service account annotated for IRSA but injected web identity environment is missing",
						Recommendation: "Verify the IRSA mutating webhook/admission path and ensure the workload is running with a service account annotated for the expected IAM role.",
						References:     append([]string{}, saSources[key]...),
					})
				}
			}
		}

		if gsa != "" && !looksLikeGSAEmail(gsa) {
			issues = append(issues, Issue{
				Kind:           "ServiceAccount",
				Namespace:      sa.Namespace,
				Name:           sa.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "workload-identity-gke",
				Summary:        fmt.Sprintf("GKE workload identity annotation looks malformed: %s", gsa),
				Recommendation: "Set iam.gke.io/gcp-service-account to a valid Google service account email and verify the IAM binding from the Kubernetes service account.",
			})
		}

		for _, pod := range podsBySA[key] {
			azureEnabled := strings.EqualFold(pod.Labels["azure.workload.identity/use"], "true")
			if azureEnabled && azureClientID == "" {
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "workload-identity-azure",
					Summary:        "pod requests Azure Workload Identity but its service account lacks azure.workload.identity/client-id",
					Recommendation: "Annotate the service account with azure.workload.identity/client-id and ensure the federated credential exists in Microsoft Entra ID.",
				})
			}
			if azureClientID != "" && !azureEnabled {
				issues = append(issues, Issue{
					Kind:           "Pod",
					Namespace:      pod.Namespace,
					Name:           pod.Name,
					Severity:       SeverityInfo,
					Category:       "security",
					Check:          "workload-identity-azure",
					Summary:        "service account is annotated for Azure Workload Identity but pod label azure.workload.identity/use=true is missing",
					Recommendation: "Add the pod label azure.workload.identity/use=true so the Azure workload identity webhook can inject the expected token configuration.",
				})
			}
		}

		if azureClientID != "" && !looksLikeUUID(azureClientID) {
			issues = append(issues, Issue{
				Kind:           "ServiceAccount",
				Namespace:      sa.Namespace,
				Name:           sa.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "workload-identity-azure",
				Summary:        fmt.Sprintf("Azure workload identity client ID looks malformed: %s", azureClientID),
				Recommendation: "Set azure.workload.identity/client-id to the application or managed identity client UUID.",
			})
		}
		if azureTenantID != "" && !looksLikeUUID(azureTenantID) {
			issues = append(issues, Issue{
				Kind:           "ServiceAccount",
				Namespace:      sa.Namespace,
				Name:           sa.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "workload-identity-azure",
				Summary:        fmt.Sprintf("Azure workload identity tenant ID looks malformed: %s", azureTenantID),
				Recommendation: "Set azure.workload.identity/tenant-id to the Microsoft Entra tenant UUID if you use an explicit tenant annotation.",
			})
		}
	}

	if provider == "eks/aws" && !hasWorkloadIdentityAnnotation(serviceAccounts, "eks.amazonaws.com/role-arn") {
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "workload-identity-irsa",
			Summary:        "cluster looks like EKS but no IRSA-annotated service accounts were detected",
			Recommendation: "If workloads need AWS API access, prefer IRSA over static cloud credentials or node-wide permissions.",
		})
	}
	if provider == "gke/gce" && !hasWorkloadIdentityAnnotation(serviceAccounts, "iam.gke.io/gcp-service-account") {
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "workload-identity-gke",
			Summary:        "cluster looks like GKE but no GKE Workload Identity annotations were detected",
			Recommendation: "If workloads need Google Cloud API access, prefer Workload Identity over static keys mounted into pods.",
		})
	}
	if provider == "aks/azure" && !hasWorkloadIdentityAnnotation(serviceAccounts, "azure.workload.identity/client-id") {
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "workload-identity-azure",
			Summary:        "cluster looks like AKS but no Azure Workload Identity annotations were detected",
			Recommendation: "If workloads need Azure API access, prefer Microsoft Entra Workload Identity over static secrets or node-wide credentials.",
		})
	}

	return issues
}

func serviceAccountKey(namespace, name string) string {
	return namespace + "/" + name
}

func ruleAllowsSecretsRead(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if hasResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch", "*"}, []string{"", "*"}) {
			return true
		}
	}
	return false
}

func isProductionNamespace(ns namespaceMeta) bool {
	if ns.name == "" {
		return false
	}
	name := strings.ToLower(ns.name)
	for _, marker := range []string{"prod", "production", "live"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	for _, source := range []map[string]string{ns.labels, ns.annotations} {
		for key, value := range source {
			keyLower := strings.ToLower(key)
			valueLower := strings.ToLower(value)
			if (strings.Contains(keyLower, "env") || strings.Contains(keyLower, "environment") || strings.Contains(keyLower, "stage") || strings.Contains(keyLower, "tier")) && (valueLower == "prod" || valueLower == "production" || valueLower == "live") {
				return true
			}
		}
	}
	return false
}

func podUsesServiceAccountToken(pod corev1.Pod, sa corev1.ServiceAccount) bool {
	if pod.Spec.AutomountServiceAccountToken != nil {
		return *pod.Spec.AutomountServiceAccountToken
	}
	if sa.AutomountServiceAccountToken != nil {
		return *sa.AutomountServiceAccountToken
	}
	return true
}

func podHasProjectedToken(pod corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			if source.ServiceAccountToken != nil {
				return true
			}
		}
	}
	return false
}

func podLooksLikeKubernetesClient(pod corev1.Pod) bool {
	keywords := []string{"kube", "kubectl", "controller", "operator", "manager", "scheduler", "autoscaler", "cert-manager", "external-dns", "argocd", "velero", "csi", "cni", "metrics-server", "prometheus-operator"}
	for _, container := range pod.Spec.Containers {
		fields := []string{container.Name, container.Image}
		fields = append(fields, container.Command...)
		fields = append(fields, container.Args...)
		for _, env := range container.Env {
			fields = append(fields, env.Name, env.Value)
		}
		for _, field := range fields {
			text := strings.ToLower(field)
			for _, keyword := range keywords {
				if strings.Contains(text, keyword) {
					return true
				}
			}
		}
	}
	return false
}

func podHasWorkloadIdentityIndicators(pod corev1.Pod, sa corev1.ServiceAccount, provider string) bool {
	if podHasEnv(pod, "AWS_WEB_IDENTITY_TOKEN_FILE") || podHasEnv(pod, "AWS_ROLE_ARN") {
		return true
	}
	if strings.EqualFold(pod.Labels["azure.workload.identity/use"], "true") {
		return true
	}
	if sa.Annotations["eks.amazonaws.com/role-arn"] != "" || sa.Annotations["iam.gke.io/gcp-service-account"] != "" || sa.Annotations["azure.workload.identity/client-id"] != "" {
		return true
	}
	return provider != "" && podHasProjectedToken(pod)
}

func podHasEnv(pod corev1.Pod, name string) bool {
	for _, container := range pod.Spec.Containers {
		for _, env := range container.Env {
			if env.Name == name {
				return true
			}
		}
	}
	return false
}

func hasWorkloadIdentityAnnotation(serviceAccounts []corev1.ServiceAccount, annotation string) bool {
	for _, sa := range serviceAccounts {
		if sa.Annotations[annotation] != "" {
			return true
		}
	}
	return false
}

func looksLikeAWSRoleARN(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) >= 6 && parts[0] == "arn" && parts[2] == "iam" && strings.Contains(value, ":role/")
}

func looksLikeGSAEmail(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "@") && strings.HasSuffix(value, ".gserviceaccount.com")
}

func looksLikeUUID(value string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "-")
	if len(parts) != 5 {
		return false
	}
	lengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != lengths[i] {
			return false
		}
		for _, ch := range part {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return false
			}
		}
	}
	return true
}
