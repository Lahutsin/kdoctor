package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestMultitenancyHelpers(t *testing.T) {
	ns := map[string]namespaceMeta{"tenant-a": {name: "tenant-a", labels: map[string]string{"tenant": "true"}, annotations: map[string]string{"workspace": "a"}}, "prod": {name: "prod", labels: map[string]string{"environment": "production", "tenant": "true"}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant-a", Labels: map[string]string{"tenant": "true"}}, Spec: corev1.PodSpec{HostNetwork: true, ServiceAccountName: "runtime", Volumes: []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}}}}
	if !looksTenantMarker("customer-workspace") || !namespaceLooksTenantScoped(ns["tenant-a"], []corev1.Pod{pod}) {
		t.Fatal("expected tenant markers")
	}
	if normalizePath("/Admin/") != "/admin" || len(sortedStringSet(map[string]struct{}{"b": {}, "a": {}})) != 2 {
		t.Fatal("unexpected multitenancy helpers")
	}
	if !podHasSensitiveHostAccess(pod) || !nodeHasIsolationTaint(corev1.Node{Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: "dedicated", Value: "tenant-a", Effect: corev1.TaintEffectNoSchedule}}}}) {
		t.Fatal("expected host access and node isolation helpers")
	}
	runtimeDeployRules := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"get", "create"}}, {APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"patch"}}}
	if !rulesTouchClusterScopedResources([]rbacv1.PolicyRule{{Resources: []string{"nodes"}}}) || !rulesAllowListWatchAcrossNamespaces([]rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"list"}}}) || !rulesAllowRuntimeAndDeployControl(runtimeDeployRules) {
		t.Fatal("expected RBAC helper matches")
	}
	if !tenantSubject(rbacv1.Subject{Kind: "ServiceAccount", Namespace: "tenant-a", Name: "runtime"}, "tenant-a", ns) || !looksSystemSubject(rbacv1.Subject{Kind: "User", Name: "system:admin"}, "") {
		t.Fatal("unexpected subject classification")
	}
	if len(tenantNamespaceIsolationIssues(ns, map[string][]corev1.Pod{"tenant-a": {pod}}, map[string][]networkingv1.NetworkPolicy{"tenant-a": {}})) == 0 {
		t.Fatal("expected tenant isolation issue")
	}
	ingresses := []networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "tenant-a"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "shared.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/app"}}}}}}}}, {ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "tenant-b"}, Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "shared.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/app"}}}}}}}}}
	if len(sharedIngressPathLeakageIssues(ingresses)) == 0 {
		t.Fatal("expected shared ingress path issue")
	}
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{"agentpool": "shared"}}}}
	if len(sharedNodePoolIsolationIssues(nodes, []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "payment-app", Namespace: "prod"}, Spec: corev1.PodSpec{NodeName: "node-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "tenant-app", Namespace: "tenant-a"}, Spec: corev1.PodSpec{NodeName: "node-a"}}}, ns)) == 0 {
		t.Fatal("expected shared node pool issue")
	}
	if len(tenantHostAccessIssues([]corev1.Pod{pod}, ns)) == 0 {
		t.Fatal("expected tenant host access issue")
	}
	saRules := map[string][]rbacv1.PolicyRule{"tenant-a/runtime": {{Resources: []string{"nodes"}, Verbs: []string{"get"}}}, "prod/runtime": runtimeDeployRules}
	if len(tenantClusterScopedAccessIssues(saRules, ns)) == 0 || len(ciRuntimeIdentitySeparationIssues([]corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod"}, Spec: corev1.PodSpec{ServiceAccountName: "runtime"}}}, saRules, map[string]corev1.ServiceAccount{"prod/runtime": {ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: "prod"}, Secrets: []corev1.ObjectReference{{Name: "token"}}}}, ns)) == 0 {
		t.Fatal("expected tenant SA issues")
	}
	if len(excessiveCrossNamespaceWatchIssues([]rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "watch-all"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "watcher"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "tenant-a", Name: "runtime"}}}}, nil, map[string]rbacRoleMeta{roleKey("ClusterRole", "", "watcher"): {rules: []rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"list", "watch"}}}}}, ns)) == 0 {
		t.Fatal("expected excessive watch issue")
	}
}

func TestCheckMultiTenancy(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/tenant-a":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: map[string]string{"tenant": "true"}}})
		case "/api/v1/namespaces/tenant-a/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant-a", Labels: map[string]string{"tenant": "true"}},
				Spec: corev1.PodSpec{
					NodeName:           "node-a",
					HostNetwork:        true,
					ServiceAccountName: "runtime",
					Volumes:            []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}},
				},
			}}})
		case "/apis/networking.k8s.io/v1/namespaces/tenant-a/networkpolicies":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.NetworkPolicyList{})
		case "/apis/networking.k8s.io/v1/namespaces/tenant-a/ingresses":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.IngressList{})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{"agentpool": "shared"}}}}})
		case "/api/v1/namespaces/tenant-a/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: "tenant-a"}}}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleBindingList{Items: []rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "watch-all"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "watcher"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "tenant-a", Name: "runtime"}}}}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/tenant-a/rolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleBindingList{})
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleList{Items: []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "watcher"}, Rules: []rbacv1.PolicyRule{{Resources: []string{"pods", "secrets"}, Verbs: []string{"list", "watch"}}}}}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/tenant-a/roles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckMultiTenancy(ctx, cs, nil, "tenant-a")
	if err != nil {
		t.Fatalf("CheckMultiTenancy returned error: %v", err)
	}
	if len(issues) < 3 {
		t.Fatalf("expected several multitenancy issues, got %+v", issues)
	}
	if _, err := CheckMultiTenancy(ctx, nil, nil, "tenant-a"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}

func TestMultitenancyCrossNamespaceAndGatewayHelpers(t *testing.T) {
	namespaces := map[string]namespaceMeta{
		"tenant-a": {name: "tenant-a", labels: map[string]string{"tenant": "true"}},
		"tenant-b": {name: "tenant-b", labels: map[string]string{"tenant": "true"}},
		"shared":   {name: "shared"},
	}
	roleIndex := map[string]rbacRoleMeta{
		roleKey("ClusterRole", "", "global-reader"): {
			kind:  "ClusterRole",
			name:  "global-reader",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets", "configmaps"}, Verbs: []string{"get", "list"}}},
		},
		roleKey("Role", "shared", "ns-reader"): {
			kind:      "Role",
			namespace: "shared",
			name:      "ns-reader",
			rules:     []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
		},
		roleKey("ClusterRole", "", "watcher"): {
			kind:  "ClusterRole",
			name:  "watcher",
			rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"list", "watch"}}},
		},
	}
	clusterBindings := []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "global-reader-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "global-reader"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice@example.com"}},
	}, {
		ObjectMeta: metav1.ObjectMeta{Name: "watcher-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "watcher"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "tenant-a", Name: "runtime"}},
	}}
	roleBindings := []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-ns-reader", Namespace: "shared"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "ns-reader"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "tenant-a", Name: "runtime"}},
	}, {
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-watch", Namespace: "tenant-b"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "watcher"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "tenant-b", Name: "runtime"}},
	}}

	if len(crossNamespaceConfigSecretAccessIssues(clusterBindings, roleBindings, roleIndex)) < 2 {
		t.Fatal("expected cross-namespace data access issues")
	}
	if len(excessiveCrossNamespaceWatchIssues(clusterBindings, roleBindings, roleIndex, namespaces)) < 2 {
		t.Fatal("expected excessive cross-namespace watch issues")
	}
	if !tenantSubject(rbacv1.Subject{Kind: "User", Name: "alice@example.com"}, "", namespaces) || !looksSystemSubject(rbacv1.Subject{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"}, "") {
		t.Fatal("expected tenant and system subject classification")
	}

	routeA := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]any{
			"name":      "tenant-a-route",
			"namespace": "tenant-a",
		},
		"spec": map[string]any{
			"hostnames": []any{"shared.example.com"},
			"rules": []any{map[string]any{
				"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/app"}}},
			}},
		},
	}}
	routeB := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]any{
			"name":      "tenant-b-route",
			"namespace": "tenant-b",
		},
		"spec": map[string]any{
			"hostnames": []any{"shared.example.com"},
			"rules": []any{map[string]any{
				"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/app"}}},
			}},
		},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{httpRouteGVR: "HTTPRouteList"},
		routeA,
		routeB,
	)
	issues := sharedGatewayRouteLeakageIssues(context.Background(), dyn, metav1.NamespaceAll)
	if len(issues) == 0 {
		t.Fatal("expected shared gateway route leakage issue")
	}
}
