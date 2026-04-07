package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func CheckMultiTenancy(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string) ([]Issue, error) {
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
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	networkPolicies, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		ingresses = &networkingv1.IngressList{}
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	serviceAccounts, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
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
	roleIndex, err := buildRoleIndex(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	saRules, _, _, err := buildServiceAccountRBACView(ctx, cs, ns, roleIndex)
	if err != nil {
		return nil, err
	}

	podsByNS := map[string][]corev1.Pod{}
	policiesByNS := map[string][]networkingv1.NetworkPolicy{}
	for _, pod := range pods.Items {
		podsByNS[pod.Namespace] = append(podsByNS[pod.Namespace], pod)
	}
	for _, policy := range networkPolicies.Items {
		policiesByNS[policy.Namespace] = append(policiesByNS[policy.Namespace], policy)
	}

	saIndex := make(map[string]corev1.ServiceAccount, len(serviceAccounts.Items))
	for _, sa := range serviceAccounts.Items {
		saIndex[serviceAccountKey(sa.Namespace, sa.Name)] = sa
	}

	issues := make([]Issue, 0)
	issues = append(issues, tenantNamespaceIsolationIssues(namespaces, podsByNS, policiesByNS)...)
	issues = append(issues, crossNamespaceConfigSecretAccessIssues(clusterRoleBindings.Items, roleBindings.Items, roleIndex)...)
	issues = append(issues, sharedIngressPathLeakageIssues(ingresses.Items)...)
	issues = append(issues, sharedGatewayRouteLeakageIssues(ctx, dyn, ns)...)
	issues = append(issues, sharedNodePoolIsolationIssues(nodes.Items, pods.Items, namespaces)...)
	issues = append(issues, tenantHostAccessIssues(pods.Items, namespaces)...)
	issues = append(issues, tenantClusterScopedAccessIssues(saRules, namespaces)...)
	issues = append(issues, excessiveCrossNamespaceWatchIssues(clusterRoleBindings.Items, roleBindings.Items, roleIndex, namespaces)...)
	issues = append(issues, ciRuntimeIdentitySeparationIssues(pods.Items, saRules, saIndex, namespaces)...)

	return dedupeIssues(issues), nil
}

func tenantNamespaceIsolationIssues(namespaces map[string]namespaceMeta, podsByNS map[string][]corev1.Pod, policiesByNS map[string][]networkingv1.NetworkPolicy) []Issue {
	issues := make([]Issue, 0)
	for _, ns := range sortedNamespaceMeta(namespaces) {
		if !namespaceLooksTenantScoped(ns, podsByNS[ns.name]) {
			continue
		}
		policies := policiesByNS[ns.name]
		if len(policies) == 0 {
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "multitenancy-namespace-isolation",
				Summary:        "tenant-like namespace has no NetworkPolicy isolation",
				Recommendation: "Add default deny ingress and egress policies for tenant namespaces and allow only explicit inter-tenant or shared-platform flows.",
			})
			continue
		}
		if !namespaceHasDefaultDeny(policies, networkingv1.PolicyTypeIngress) || !namespaceHasDefaultDeny(policies, networkingv1.PolicyTypeEgress) {
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "multitenancy-default-deny-gap",
				Summary:        "tenant-like namespace lacks full default deny network isolation",
				Recommendation: "Use both ingress and egress default deny policies in tenant namespaces before adding granular allows.",
			})
		}
		if level := psaLevel(ns.labels, "enforce"); level == "" || level == "privileged" {
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "multitenancy-psa-gap",
				Summary:        fmt.Sprintf("tenant-like namespace uses weak or missing Pod Security enforcement (%s)", displayPSALevel(level)),
				Recommendation: "Prefer restricted Pod Security Admission for tenant workloads and document any weaker baseline explicitly.",
			})
		}
	}
	return issues
}

func crossNamespaceConfigSecretAccessIssues(clusterRoleBindings []rbacv1.ClusterRoleBinding, roleBindings []rbacv1.RoleBinding, roleIndex map[string]rbacRoleMeta) []Issue {
	issues := make([]Issue, 0)
	for _, binding := range clusterRoleBindings {
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, "", binding.RoleRef.Name)]
		if !ok || !(ruleAllowsSecretsRead(meta.rules) || ruleAllowsConfigMapRead(meta.rules)) {
			continue
		}
		for _, subject := range binding.Subjects {
			if looksSystemSubject(subject, "") {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "ClusterRoleBinding",
				Name:           binding.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "multitenancy-cross-namespace-data-access",
				Summary:        fmt.Sprintf("binding %s grants cross-namespace secret/config read capability to %s", binding.Name, formatSubject(subject, "")),
				Recommendation: "Replace cluster-wide secret/config read access with namespace-scoped bindings, explicit brokering, or per-tenant data delivery mechanisms.",
			})
		}
	}
	for _, binding := range roleBindings {
		roleNS := binding.Namespace
		if strings.EqualFold(binding.RoleRef.Kind, "ClusterRole") {
			roleNS = ""
		}
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, roleNS, binding.RoleRef.Name)]
		if !ok || !(ruleAllowsSecretsRead(meta.rules) || ruleAllowsConfigMapRead(meta.rules)) {
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
			if subjectNamespace == binding.Namespace {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "RoleBinding",
				Namespace:      binding.Namespace,
				Name:           binding.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "multitenancy-cross-namespace-data-access",
				Summary:        fmt.Sprintf("rolebinding allows service account %s/%s to read data in another namespace", subjectNamespace, subject.Name),
				Recommendation: "Avoid cross-namespace secret/config access for tenant service accounts unless it is explicitly brokered and reviewed.",
			})
		}
	}
	return issues
}

func sharedIngressPathLeakageIssues(ingresses []networkingv1.Ingress) []Issue {
	buckets := map[string]map[string]struct{}{}
	for _, ingress := range ingresses {
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP == nil || strings.TrimSpace(rule.Host) == "" {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				key := strings.ToLower(rule.Host + normalizePath(path.Path))
				if buckets[key] == nil {
					buckets[key] = map[string]struct{}{}
				}
				buckets[key][ingress.Namespace] = struct{}{}
			}
		}
	}
	issues := make([]Issue, 0)
	for key, namespaces := range buckets {
		if len(namespaces) < 2 {
			continue
		}
		nsList := sortedStringSet(namespaces)
		issues = append(issues, Issue{
			Kind:           "Ingress",
			Name:           key,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "multitenancy-shared-ingress-path",
			Summary:        fmt.Sprintf("the same host/path is routed by multiple namespaces: %s", strings.Join(nsList, ", ")),
			Recommendation: "Avoid sharing the same ingress host/path prefixes across tenants unless traffic partitioning and auth boundaries are explicit and tested.",
		})
	}
	return issues
}

func sharedGatewayRouteLeakageIssues(ctx context.Context, dyn dynamic.Interface, namespace string) []Issue {
	if dyn == nil {
		return nil
	}
	var (
		routes *unstructured.UnstructuredList
		err    error
	)
	if namespace != metav1.NamespaceAll {
		routes, err = dyn.Resource(httpRouteGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	} else {
		routes, err = dyn.Resource(httpRouteGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil
	}
	buckets := map[string]map[string]struct{}{}
	for _, route := range routes.Items {
		hosts, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
		paths := httpRoutePaths(route)
		for _, host := range hosts {
			for _, path := range paths {
				key := strings.ToLower(host + normalizePath(path))
				if buckets[key] == nil {
					buckets[key] = map[string]struct{}{}
				}
				buckets[key][route.GetNamespace()] = struct{}{}
			}
		}
	}
	issues := make([]Issue, 0)
	for key, namespaces := range buckets {
		if len(namespaces) < 2 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Gateway",
			Name:           key,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "multitenancy-shared-gateway-path",
			Summary:        fmt.Sprintf("the same Gateway API host/path is used across namespaces: %s", strings.Join(sortedStringSet(namespaces), ", ")),
			Recommendation: "Avoid shared Gateway API routes across tenants unless route ownership, auth, and backend isolation are explicitly separated.",
		})
	}
	return issues
}

func sharedNodePoolIsolationIssues(nodes []corev1.Node, pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	type poolInfo struct {
		namespaces map[string]struct{}
		isolated   int
		nodes      int
		sensitive  bool
	}
	nodePoolByNode := map[string]string{}
	pools := map[string]*poolInfo{}
	for _, node := range nodes {
		pool := nodePoolName(node.Labels)
		if pool == "" || pool == "ungrouped" {
			continue
		}
		nodePoolByNode[node.Name] = pool
		info := pools[pool]
		if info == nil {
			info = &poolInfo{namespaces: map[string]struct{}{}}
			pools[pool] = info
		}
		info.nodes++
		if nodeHasIsolationTaint(node) {
			info.isolated++
		}
	}
	for _, pod := range pods {
		pool := nodePoolByNode[pod.Spec.NodeName]
		if pool == "" {
			continue
		}
		info := pools[pool]
		info.namespaces[pod.Namespace] = struct{}{}
		if isSensitiveWorkload(pod, namespaces[pod.Namespace]) {
			info.sensitive = true
		}
	}
	issues := make([]Issue, 0)
	for pool, info := range pools {
		if !info.sensitive || len(info.namespaces) < 2 {
			continue
		}
		if info.nodes > 0 && info.isolated == info.nodes {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           pool,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "multitenancy-shared-nodepool",
			Summary:        fmt.Sprintf("sensitive and other tenant workloads share node pool %s without clear tenant-isolation taints", pool),
			Recommendation: "Use dedicated tainted node pools or stricter node selectors/affinity for trusted or high-sensitivity workloads.",
		})
	}
	return issues
}

func tenantHostAccessIssues(pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if looksLikeSystemNamespace(pod.Namespace) || !namespaceLooksTenantScoped(namespaces[pod.Namespace], []corev1.Pod{pod}) {
			continue
		}
		if !pod.Spec.HostNetwork && !pod.Spec.HostPID && !pod.Spec.HostIPC && !podHasSensitiveHostAccess(pod) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "multitenancy-tenant-host-access",
			Summary:        "tenant workload has direct host access or host namespace exposure",
			Recommendation: "Do not allow tenant workloads to run privileged, use host namespaces, or mount host paths unless they are isolated to dedicated trusted nodes.",
		})
	}
	return issues
}

func tenantClusterScopedAccessIssues(saRules map[string][]rbacv1.PolicyRule, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for key, rules := range saRules {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 || looksLikeSystemNamespace(parts[0]) || !namespaceLooksTenantScoped(namespaces[parts[0]], nil) {
			continue
		}
		if !rulesTouchClusterScopedResources(rules) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      parts[0],
			Name:           parts[1],
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "multitenancy-cluster-scoped-access",
			Summary:        "tenant service account has access to cluster-scoped controllers or resources",
			Recommendation: "Keep tenant identities away from CRDs, cluster roles, webhooks, nodes, namespaces, and other cluster-scoped control surfaces.",
		})
	}
	return issues
}

func excessiveCrossNamespaceWatchIssues(clusterRoleBindings []rbacv1.ClusterRoleBinding, roleBindings []rbacv1.RoleBinding, roleIndex map[string]rbacRoleMeta, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, binding := range clusterRoleBindings {
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, "", binding.RoleRef.Name)]
		if !ok || !rulesAllowListWatchAcrossNamespaces(meta.rules) {
			continue
		}
		for _, subject := range binding.Subjects {
			if !tenantSubject(subject, "", namespaces) {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "ClusterRoleBinding",
				Name:           binding.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "multitenancy-list-watch-cross-namespace",
				Summary:        fmt.Sprintf("tenant subject %s can list/watch resources across namespaces", formatSubject(subject, "")),
				Recommendation: "Avoid granting tenant identities cluster-wide list/watch access unless the access pattern is explicitly required and audited.",
			})
		}
	}
	for _, binding := range roleBindings {
		roleNS := binding.Namespace
		if strings.EqualFold(binding.RoleRef.Kind, "ClusterRole") {
			roleNS = ""
		}
		meta, ok := roleIndex[roleKey(binding.RoleRef.Kind, roleNS, binding.RoleRef.Name)]
		if !ok || !rulesAllowListWatchAcrossNamespaces(meta.rules) {
			continue
		}
		for _, subject := range binding.Subjects {
			if !tenantSubject(subject, binding.Namespace, namespaces) {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "RoleBinding",
				Namespace:      binding.Namespace,
				Name:           binding.Name,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "multitenancy-list-watch-cross-namespace",
				Summary:        fmt.Sprintf("tenant subject %s receives broad list/watch access in namespace %s", formatSubject(subject, binding.Namespace), binding.Namespace),
				Recommendation: "Reduce list/watch to only the namespaces and resource kinds truly needed by the tenant workload or automation.",
			})
		}
	}
	return issues
}

func ciRuntimeIdentitySeparationIssues(pods []corev1.Pod, saRules map[string][]rbacv1.PolicyRule, serviceAccounts map[string]corev1.ServiceAccount, namespaces map[string]namespaceMeta) []Issue {
	usage := serviceAccountUsage(pods)
	issues := make([]Issue, 0)
	for key, count := range usage {
		if count == 0 {
			continue
		}
		rules := saRules[key]
		if !rulesAllowRuntimeAndDeployControl(rules) {
			continue
		}
		parts := strings.SplitN(key, "/", 2)
		severity := SeverityWarning
		if isProductionNamespace(namespaces[parts[0]]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "ServiceAccount",
			Namespace:      parts[0],
			Name:           parts[1],
			Severity:       severity,
			Category:       "security",
			Check:          "multitenancy-cicd-runtime-identity",
			Summary:        fmt.Sprintf("service account is used by running pods and also has deployment/change-control permissions (%d pods)", count),
			Recommendation: "Separate CI/CD and runtime identities so running workloads do not also carry rollout, patch, or broad secret-management permissions.",
			References:     []string{fmt.Sprintf("tokenSecrets=%d", len(serviceAccounts[key].Secrets))},
		})
	}
	return issues
}

func namespaceLooksTenantScoped(ns namespaceMeta, pods []corev1.Pod) bool {
	if ns.name == "" || looksLikeSystemNamespace(ns.name) {
		return false
	}
	fields := []string{ns.name}
	for _, source := range []map[string]string{ns.labels, ns.annotations} {
		for key, value := range source {
			fields = append(fields, key, value)
		}
	}
	for _, pod := range pods {
		fields = append(fields, pod.Name, pod.Spec.ServiceAccountName)
		for _, source := range []map[string]string{pod.Labels, pod.Annotations} {
			for key, value := range source {
				fields = append(fields, key, value)
			}
		}
	}
	for _, field := range fields {
		if looksTenantMarker(field) {
			return true
		}
	}
	return false
}

func looksTenantMarker(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	if text == "" {
		return false
	}
	for _, marker := range []string{"tenant", "tenancy", "customer", "workspace", "shared-tenant"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func ruleAllowsConfigMapRead(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if hasResourceVerb(rule, []string{"configmaps"}, []string{"get", "list", "watch", "*"}, []string{"", "*"}) {
			return true
		}
	}
	return false
}

func normalizePath(path string) string {
	path = strings.TrimSpace(strings.ToLower(path))
	if path == "" {
		return "/"
	}
	return strings.TrimSuffix(path, "/")
}

func sortedStringSet(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for key := range values {
		items = append(items, key)
	}
	sort.Strings(items)
	return items
}

func podHasSensitiveHostAccess(pod corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil && (sensitiveNodeHostPath(volume.HostPath.Path) || looksLikeRuntimeSocket(volume.HostPath.Path)) {
			return true
		}
	}
	for _, container := range allSecurityContainers(pod) {
		if isPrivileged(container.securityContext) {
			return true
		}
	}
	return false
}

func nodeHasIsolationTaint(node corev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		if looksTenantMarker(taint.Key) || looksTenantMarker(taint.Value) || strings.Contains(strings.ToLower(taint.Key), "dedicated") || strings.Contains(strings.ToLower(taint.Value), "dedicated") || strings.Contains(strings.ToLower(taint.Key), "isolation") || strings.Contains(strings.ToLower(taint.Value), "isolation") {
			return true
		}
	}
	return false
}

func rulesTouchClusterScopedResources(rules []rbacv1.PolicyRule) bool {
	clusterResources := []string{"nodes", "namespaces", "clusterroles", "clusterrolebindings", "customresourcedefinitions", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "apiservices", "persistentvolumes", "storageclasses", "csidrivers", "certificatesigningrequests"}
	for _, rule := range rules {
		if hasWildcard(rule.Resources) {
			return true
		}
		for _, resource := range rule.Resources {
			base := strings.Split(resource, "/")[0]
			if containsString(clusterResources, base) {
				return true
			}
		}
	}
	return false
}

func rulesAllowListWatchAcrossNamespaces(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if !sliceIntersects(rule.Verbs, []string{"list", "watch", "*"}) {
			continue
		}
		if hasWildcard(rule.Resources) || sliceIntersects(rule.Resources, []string{"pods", "configmaps", "secrets", "namespaces", "services"}) {
			return true
		}
	}
	return false
}

func tenantSubject(subject rbacv1.Subject, bindingNamespace string, namespaces map[string]namespaceMeta) bool {
	if strings.EqualFold(subject.Kind, "ServiceAccount") {
		ns := subject.Namespace
		if ns == "" {
			ns = bindingNamespace
		}
		return namespaceLooksTenantScoped(namespaces[ns], nil)
	}
	name := strings.ToLower(subject.Name)
	return !strings.HasPrefix(name, "system:") && !strings.Contains(name, "node")
}

func looksSystemSubject(subject rbacv1.Subject, bindingNamespace string) bool {
	if strings.EqualFold(subject.Kind, "ServiceAccount") {
		ns := subject.Namespace
		if ns == "" {
			ns = bindingNamespace
		}
		return isSystemNamespace(ns)
	}
	return strings.HasPrefix(strings.ToLower(subject.Name), "system:")
}

func rulesAllowRuntimeAndDeployControl(rules []rbacv1.PolicyRule) bool {
	hasRuntime := false
	hasDeploy := false
	for _, rule := range rules {
		if hasResourceVerb(rule, []string{"pods", "pods/exec", "pods/attach", "secrets"}, []string{"get", "list", "watch", "create", "*"}, []string{"", "*"}) {
			hasRuntime = true
		}
		if hasResourceVerb(rule, []string{"deployments", "daemonsets", "statefulsets", "replicasets"}, []string{"patch", "update", "create", "delete", "*"}, []string{"apps", "extensions", "*"}) || hasResourceVerb(rule, []string{"jobs", "cronjobs"}, []string{"patch", "update", "create", "delete", "*"}, []string{"batch", "*"}) {
			hasDeploy = true
		}
	}
	return hasRuntime && hasDeploy
}
