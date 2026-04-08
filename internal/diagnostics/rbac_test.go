package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRBACHelpersAndCheckRBAC(t *testing.T) {
	meta := rbacRoleMeta{kind: "ClusterRole", name: "wild", rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	if len(wildcardRoleIssues(meta)) == 0 || len(dangerousPermissionFindings(meta.rules)) == 0 || !roleHasDangerousPrivilege(meta.rules) {
		t.Fatal("expected dangerous wildcard RBAC findings")
	}
	issues := evaluateBindingSubjects("ClusterRoleBinding", "admins", "", rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}, {Kind: "Group", Name: "legacy-admins"}}, meta)
	if len(issues) < 2 {
		t.Fatalf("expected binding subject issues, got %+v", issues)
	}
	perms := map[string]*subjectPermission{}
	accumulateServiceAccountPermissions(perms, []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "prod", Name: "default"}}, meta.rules, "ClusterRoleBinding/admins")
	if len(perms) != 1 {
		t.Fatal("expected accumulated service account permission entry")
	}
	saIndex := map[string]corev1.ServiceAccount{"prod/default": {ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}, Secrets: []corev1.ObjectReference{{Name: "token"}}}, "kube-system/custom": {ObjectMeta: metav1.ObjectMeta{Name: "custom", Namespace: "kube-system"}}}
	usage := map[string]int{"prod/default": 0, "kube-system/custom": 1}
	if len(dangerousServiceAccountIssues(perms, usage, saIndex)) == 0 || len(defaultServiceAccountIssues(perms)) == 0 {
		t.Fatal("expected dangerous/default serviceaccount issues")
	}
	perms["kube-system/custom"] = &subjectPermission{subject: rbacv1.Subject{Kind: "ServiceAccount", Namespace: "kube-system", Name: "custom"}, rules: meta.rules}
	if len(systemNamespaceServiceAccountIssues(perms)) == 0 {
		t.Fatal("expected system namespace service account issue")
	}
	if !roleSeemsNamespaced([]rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"get"}}}) || !hasVerb(rbacv1.PolicyRule{Verbs: []string{"bind"}}, []string{"bind"}) {
		t.Fatal("expected role helper behavior")
	}
	if qualifiedName("prod", "api") != "prod/api" || !looksExpectedSystemServiceAccount("kube-proxy") || !isIdentityGroupReviewSubject("legacy-admins") {
		t.Fatal("unexpected RBAC helper behavior")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleList{Items: []rbacv1.ClusterRole{{
				ObjectMeta: metav1.ObjectMeta{Name: "wild"},
				Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
				Rules:      []rbacv1.PolicyRule{{Resources: []string{"pods"}, Verbs: []string{"create"}}},
			}}})
		case "/apis/rbac.authorization.k8s.io/v1/roles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleList{})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleBindingList{Items: []rbacv1.ClusterRoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "broad-users"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}, {Kind: "ServiceAccount", Namespace: "prod", Name: "default"}},
			}}})
		case "/apis/rbac.authorization.k8s.io/v1/rolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleBindingList{})
		case "/api/v1/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}, Secrets: []corev1.ObjectReference{{Name: "token"}}}}})
		case "/api/v1/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckRBAC(ctx, cs, "")
	if err != nil {
		t.Fatalf("CheckRBAC returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several RBAC issues, got %+v", issues)
	}
	if _, err := CheckRBAC(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
