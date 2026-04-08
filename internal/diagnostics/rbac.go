package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type rbacRoleMeta struct {
	kind      string
	namespace string
	name      string
	rules     []rbacv1.PolicyRule
}

type subjectPermission struct {
	subject  rbacv1.Subject
	rules    []rbacv1.PolicyRule
	sources  []string
	critical bool
}

func CheckRBAC(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	clusterRoles, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	roles, err := cs.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	clusterRoleBindings, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	roleBindings, err := cs.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
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

	roleIndex := make(map[string]rbacRoleMeta)
	issues := make([]Issue, 0)
	for _, role := range clusterRoles.Items {
		meta := rbacRoleMeta{kind: "ClusterRole", name: role.Name, rules: role.Rules}
		roleIndex[roleKey("ClusterRole", "", role.Name)] = meta
		issues = append(issues, wildcardRoleIssues(meta)...)
	}
	for _, role := range roles.Items {
		meta := rbacRoleMeta{kind: "Role", namespace: role.Namespace, name: role.Name, rules: role.Rules}
		roleIndex[roleKey("Role", role.Namespace, role.Name)] = meta
		issues = append(issues, wildcardRoleIssues(meta)...)
	}

	saPermissions := map[string]*subjectPermission{}
	saUsage := serviceAccountUsage(pods.Items)
	serviceAccountIndex := make(map[string]corev1.ServiceAccount)
	for _, sa := range serviceAccounts.Items {
		serviceAccountIndex[sa.Namespace+"/"+sa.Name] = sa
	}

	for _, binding := range clusterRoleBindings.Items {
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, "", binding.RoleRef.Name)]
		if !ok {
			continue
		}
		issues = append(issues, evaluateBindingSubjects("ClusterRoleBinding", binding.Name, "", binding.RoleRef, binding.Subjects, meta)...)
		if roleSeemsNamespaced(meta.rules) {
			issues = append(issues, Issue{
				Kind:           "ClusterRoleBinding",
				Name:           binding.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "rbac-overbroad-clusterrolebinding",
				Summary:        fmt.Sprintf("clusterrolebinding %s grants a mostly namespaced role cluster-wide", binding.Name),
				Recommendation: "Consider using RoleBinding instead of ClusterRoleBinding when the permission set does not need cluster scope.",
			})
		}
		accumulateServiceAccountPermissions(saPermissions, binding.Subjects, meta.rules, "ClusterRoleBinding/"+binding.Name)
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
		issues = append(issues, evaluateBindingSubjects("RoleBinding", binding.Name, binding.Namespace, binding.RoleRef, binding.Subjects, meta)...)
		accumulateServiceAccountPermissions(saPermissions, binding.Subjects, meta.rules, "RoleBinding/"+binding.Namespace+"/"+binding.Name)
	}

	issues = append(issues, dangerousServiceAccountIssues(saPermissions, saUsage, serviceAccountIndex)...)
	issues = append(issues, defaultServiceAccountIssues(saPermissions)...)
	issues = append(issues, systemNamespaceServiceAccountIssues(saPermissions)...)

	return dedupeIssues(issues), nil
}

func wildcardRoleIssues(role rbacRoleMeta) []Issue {
	issues := make([]Issue, 0)
	for _, rule := range role.rules {
		if hasWildcard(rule.Verbs) || hasWildcard(rule.Resources) || hasWildcard(rule.APIGroups) || hasWildcard(rule.NonResourceURLs) {
			issues = append(issues, Issue{
				Kind:           role.kind,
				Namespace:      role.namespace,
				Name:           role.name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "rbac-wildcard-rule",
				Summary:        fmt.Sprintf("%s %s contains wildcard RBAC rules", strings.ToLower(role.kind), qualifiedName(role.namespace, role.name)),
				Recommendation: "Replace wildcard apiGroups/resources/verbs with only the exact permissions required.",
			})
			break
		}
	}
	return issues
}

func evaluateBindingSubjects(bindingKind, bindingName, namespace string, roleRef rbacv1.RoleRef, subjects []rbacv1.Subject, meta rbacRoleMeta) []Issue {
	issues := make([]Issue, 0)
	for _, subject := range subjects {
		subjectName := formatSubject(subject, namespace)
		if strings.EqualFold(subject.Kind, "Group") && (subject.Name == "system:unauthenticated" || subject.Name == "system:authenticated") {
			issues = append(issues, Issue{
				Kind:           bindingKind,
				Namespace:      namespace,
				Name:           bindingName,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "rbac-broad-system-group",
				Summary:        fmt.Sprintf("%s grants permissions to %s", strings.ToLower(bindingKind), subject.Name),
				Recommendation: "Remove bindings to system:authenticated or system:unauthenticated unless this exposure is explicitly intended.",
			})
		}
		if strings.EqualFold(roleRef.Kind, "ClusterRole") && roleRef.Name == "cluster-admin" {
			severity := SeverityCritical
			if bindingKind == "RoleBinding" {
				severity = SeverityWarning
			}
			issues = append(issues, Issue{
				Kind:           bindingKind,
				Namespace:      namespace,
				Name:           bindingName,
				Severity:       severity,
				Category:       "security",
				Check:          "rbac-cluster-admin-binding",
				Summary:        fmt.Sprintf("%s binds cluster-admin to %s", strings.ToLower(bindingKind), subjectName),
				Recommendation: "Replace cluster-admin with a least-privilege role tailored to the subject's actual needs.",
			})
		}
		if strings.EqualFold(subject.Kind, "Group") && isIdentityGroupReviewSubject(subject.Name) && (roleRef.Name == "cluster-admin" || roleHasDangerousPrivilege(meta.rules)) {
			issues = append(issues, Issue{
				Kind:           bindingKind,
				Namespace:      namespace,
				Name:           bindingName,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "rbac-identity-group-review",
				Summary:        fmt.Sprintf("binding %s references identity group %s with elevated privileges", bindingName, subject.Name),
				Recommendation: "Verify the external identity group still exists, has correct membership, and still needs this level of access.",
			})
		}
	}
	return issues
}

func accumulateServiceAccountPermissions(target map[string]*subjectPermission, subjects []rbacv1.Subject, rules []rbacv1.PolicyRule, source string) {
	for _, subject := range subjects {
		if !strings.EqualFold(subject.Kind, "ServiceAccount") {
			continue
		}
		namespace := subject.Namespace
		if namespace == "" {
			continue
		}
		key := namespace + "/" + subject.Name
		perm := target[key]
		if perm == nil {
			perm = &subjectPermission{subject: subject}
			target[key] = perm
		}
		perm.rules = append(perm.rules, rules...)
		perm.sources = append(perm.sources, source)
	}
}

func dangerousServiceAccountIssues(saPermissions map[string]*subjectPermission, usage map[string]int, saIndex map[string]corev1.ServiceAccount) []Issue {
	issues := make([]Issue, 0)
	for key, perm := range saPermissions {
		dangers := dangerousPermissionFindings(perm.rules)
		if len(dangers) == 0 {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		ns, name := parts[0], parts[1]
		sev := SeverityWarning
		if containsString(dangers, "cluster-admin") || containsString(dangers, "bind") || containsString(dangers, "escalate") || containsString(dangers, "impersonate") {
			sev = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      ns,
			Name:           name,
			Severity:       sev,
			Category:       "security",
			Check:          "rbac-dangerous-serviceaccount",
			Summary:        fmt.Sprintf("service account has dangerous RBAC privileges: %s", strings.Join(dangers, ", ")),
			Recommendation: "Reduce the service account to least privilege and split high-risk capabilities into separate tightly-scoped identities.",
			References:     uniqueStrings(perm.sources),
		})
		if usage[key] == 0 {
			issues = append(issues, Issue{
				Kind:           "ServiceAccount",
				Namespace:      ns,
				Name:           name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "rbac-unused-privileged-serviceaccount",
				Summary:        "high-privilege service account is not used by any current pod",
				Recommendation: "Delete or de-privilege unused service accounts so stale credentials cannot be abused later.",
			})
		}
		if sa, ok := saIndex[key]; ok && len(sa.Secrets) > 0 && sev == SeverityCritical {
			issues = append(issues, Issue{
				Kind:           "ServiceAccount",
				Namespace:      ns,
				Name:           name,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "rbac-serviceaccount-token-surface",
				Summary:        fmt.Sprintf("service account references %d secret-backed tokens", len(sa.Secrets)),
				Recommendation: "Prefer projected tokens or workload identity for privileged service accounts instead of static secret-backed tokens.",
			})
		}
	}
	return issues
}

func defaultServiceAccountIssues(saPermissions map[string]*subjectPermission) []Issue {
	issues := make([]Issue, 0)
	for key, perm := range saPermissions {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 || parts[1] != "default" {
			continue
		}
		dangers := dangerousPermissionFindings(perm.rules)
		if len(dangers) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      parts[0],
			Name:           parts[1],
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "rbac-default-serviceaccount",
			Summary:        fmt.Sprintf("default service account has elevated privileges: %s", strings.Join(dangers, ", ")),
			Recommendation: "Avoid granting privileges to the default service account; create dedicated service accounts per workload.",
		})
	}
	return issues
}

func systemNamespaceServiceAccountIssues(saPermissions map[string]*subjectPermission) []Issue {
	issues := make([]Issue, 0)
	for key, perm := range saPermissions {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 || !isSystemNamespace(parts[0]) {
			continue
		}
		dangers := dangerousPermissionFindings(perm.rules)
		if len(dangers) == 0 {
			continue
		}
		if parts[0] == metav1.NamespaceSystem && looksExpectedSystemServiceAccount(parts[1]) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      parts[0],
			Name:           parts[1],
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "rbac-system-namespace-serviceaccount",
			Summary:        fmt.Sprintf("service account in system namespace has elevated privileges: %s", strings.Join(dangers, ", ")),
			Recommendation: "Verify the service account is expected in a system namespace and restrict its permissions to the minimum set required.",
		})
	}
	return issues
}

func dangerousPermissionFindings(rules []rbacv1.PolicyRule) []string {
	found := map[string]struct{}{}
	for _, rule := range rules {
		if hasResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch", "*"}, []string{"", "*"}) {
			found["secrets-read"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"pods/exec", "pods/attach", "pods/portforward"}, []string{"create", "get", "*"}, []string{"", "*"}) {
			found["pods-exec"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"tokenreviews"}, []string{"create", "*"}, []string{"authentication.k8s.io", "*"}) {
			found["tokenreviews"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"subjectaccessreviews", "selfsubjectaccessreviews", "localsubjectaccessreviews"}, []string{"create", "*"}, []string{"authorization.k8s.io", "*"}) {
			found["subjectaccessreviews"] = struct{}{}
		}
		if hasVerb(rule, []string{"impersonate", "*"}) {
			found["impersonate"] = struct{}{}
		}
		if hasVerb(rule, []string{"bind", "*"}) {
			found["bind"] = struct{}{}
		}
		if hasVerb(rule, []string{"escalate", "*"}) {
			found["escalate"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"pods"}, []string{"create", "*"}, []string{"", "*"}) {
			found["create-pods"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"deployments", "daemonsets", "statefulsets", "replicasets"}, []string{"patch", "update", "*"}, []string{"apps", "extensions", "*"}) {
			found["patch-deployments"] = struct{}{}
		}
		if hasResourceVerb(rule, []string{"jobs", "cronjobs"}, []string{"patch", "update", "*"}, []string{"batch", "*"}) {
			found["patch-jobs"] = struct{}{}
		}
		if hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) {
			found["wildcard-rbac"] = struct{}{}
		}
	}
	return sortedKeys(found)
}

func roleHasDangerousPrivilege(rules []rbacv1.PolicyRule) bool {
	return len(dangerousPermissionFindings(rules)) > 0
}

func roleSeemsNamespaced(rules []rbacv1.PolicyRule) bool {
	if len(rules) == 0 {
		return false
	}
	clusterScoped := map[string]struct{}{
		"nodes": {}, "namespaces": {}, "persistentvolumes": {}, "clusterroles": {}, "clusterrolebindings": {}, "customresourcedefinitions": {}, "mutatingwebhookconfigurations": {}, "validatingwebhookconfigurations": {}, "apiservices": {}, "storageclasses": {}, "csidrivers": {}, "volumeattachments": {}, "certificatesigningrequests": {},
	}
	for _, rule := range rules {
		if len(rule.NonResourceURLs) > 0 || hasWildcard(rule.Resources) {
			return false
		}
		for _, resource := range rule.Resources {
			base := strings.Split(resource, "/")[0]
			if _, ok := clusterScoped[base]; ok {
				return false
			}
		}
	}
	return true
}

func serviceAccountUsage(pods []corev1.Pod) map[string]int {
	usage := map[string]int{}
	for _, pod := range pods {
		name := pod.Spec.ServiceAccountName
		if name == "" {
			name = "default"
		}
		usage[pod.Namespace+"/"+name]++
	}
	return usage
}

func roleKey(kind, namespace, name string) string {
	if strings.EqualFold(kind, "ClusterRole") {
		return "clusterrole/" + name
	}
	return "role/" + namespace + "/" + name
}

func hasWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func hasVerb(rule rbacv1.PolicyRule, verbs []string) bool {
	for _, verb := range rule.Verbs {
		for _, expected := range verbs {
			if verb == expected {
				return true
			}
		}
	}
	return false
}

func hasResourceVerb(rule rbacv1.PolicyRule, resources, verbs, apiGroups []string) bool {
	if !sliceIntersects(rule.APIGroups, apiGroups) {
		return false
	}
	if !sliceIntersects(rule.Verbs, verbs) {
		return false
	}
	return sliceIntersects(rule.Resources, resources)
}

func sliceIntersects(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func formatSubject(subject rbacv1.Subject, bindingNamespace string) string {
	if strings.EqualFold(subject.Kind, "ServiceAccount") {
		ns := subject.Namespace
		if ns == "" {
			ns = bindingNamespace
		}
		return fmt.Sprintf("ServiceAccount/%s/%s", ns, subject.Name)
	}
	return fmt.Sprintf("%s/%s", subject.Kind, subject.Name)
}

func qualifiedName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func isSystemNamespace(namespace string) bool {
	return namespace == metav1.NamespaceSystem || namespace == metav1.NamespacePublic || namespace == "kube-node-lease"
}

func looksExpectedSystemServiceAccount(name string) bool {
	for _, prefix := range []string{"kube-", "coredns", "calico", "cilium", "flannel", "antrea", "aws-", "ebs-", "efs-", "snapshot-", "metrics-server", "cert-manager", "external-dns", "istio-", "weave-", "node-"} {
		if strings.HasPrefix(name, prefix) || name == prefix {
			return true
		}
	}
	return false
}

func isIdentityGroupReviewSubject(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "system:") {
		return false
	}
	for _, marker := range []string{"legacy", "deprecated", "old", "disabled", "sso", "oidc", "aad", "okta", "google", "github", "gitlab"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return strings.Contains(name, "admin")
}

func dedupeIssues(issues []Issue) []Issue {
	seen := map[string]struct{}{}
	result := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		issue = NormalizeIssue(issue)
		key := issue.Key() + "|" + issue.Recommendation
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, issue)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if severityRank(result[i].Severity) != severityRank(result[j].Severity) {
			return severityRank(result[i].Severity) > severityRank(result[j].Severity)
		}
		return result[i].Summary < result[j].Summary
	})
	return result
}
