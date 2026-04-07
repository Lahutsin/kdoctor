package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceAccountHelpersAndCheckServiceAccountsAndTokens(t *testing.T) {
	if !ruleAllowsSecretsRead([]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}) {
		t.Fatal("expected secret-read rule detection")
	}
	if serviceAccountKey("prod", "api") != "prod/api" || !isProductionNamespace(namespaceMeta{name: "prod"}) {
		t.Fatal("unexpected namespace or service-account key helper")
	}
	if !looksLikeAWSRoleARN("arn:aws:iam::123456789012:role/app") || !looksLikeGSAEmail("svc@proj.iam.gserviceaccount.com") || !looksLikeUUID("123e4567-e89b-12d3-a456-426614174000") {
		t.Fatal("expected workload identity format helpers to match")
	}

	sa := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod", Annotations: map[string]string{"eks.amazonaws.com/role-arn": "bad-arn", "azure.workload.identity/client-id": "bad-client"}}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"azure.workload.identity/use": "true"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "app", Containers: []corev1.Container{{Name: "api", Env: []corev1.EnvVar{{Name: "KUBERNETES_SERVICE_HOST", Value: "10.0.0.1"}}}}, Volumes: []corev1.Volume{{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{ExpirationSeconds: func() *int64 { v := int64(90001); return &v }()}}}}}}}},
	}
	if !podUsesServiceAccountToken(pod, sa) || !podHasProjectedToken(pod) || !podHasEnv(pod, "KUBERNETES_SERVICE_HOST") {
		t.Fatal("expected projected token helpers to match")
	}
	if !podHasWorkloadIdentityIndicators(pod, sa, "eks/aws") || podLooksLikeKubernetesClient(corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}}}) {
		t.Fatal("unexpected workload identity or client helper behavior")
	}
	if !hasWorkloadIdentityAnnotation([]corev1.ServiceAccount{sa}, "eks.amazonaws.com/role-arn") {
		t.Fatal("expected workload identity annotation detection")
	}
	if len(projectedTokenLifetimeIssues([]corev1.Pod{pod})) == 0 {
		t.Fatal("expected projected token lifetime issue")
	}
	if len(serviceAccountAutomountIssues([]corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod"}}}, []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}, Spec: corev1.PodSpec{ServiceAccountName: "app"}}}, map[string]namespaceMeta{"prod": {name: "prod", labels: map[string]string{"environment": "production"}}}, map[string][]rbacv1.PolicyRule{"prod/app": {{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}})) == 0 {
		t.Fatal("expected automount issue")
	}
	if len(defaultServiceAccountUsageIssues([]corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}}}, map[string]namespaceMeta{"prod": {name: "prod", labels: map[string]string{"environment": "production"}}})) == 0 {
		t.Fatal("expected default service account issue")
	}
	if len(workloadIdentityIssues([]corev1.ServiceAccount{sa}, []corev1.Pod{pod}, "eks/aws", map[string][]string{"prod/app": {"ClusterRoleBinding/read-secrets"}})) == 0 {
		t.Fatal("expected workload identity issues")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{
				{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod", Annotations: map[string]string{"eks.amazonaws.com/role-arn": "bad-arn"}}},
			}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "uses-default", Namespace: "prod"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "uses-app", Namespace: "prod"}, Spec: corev1.PodSpec{ServiceAccountName: "app", Containers: []corev1.Container{{Name: "app"}}}},
			}})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{Spec: corev1.NodeSpec{ProviderID: "aws:///zone/i-1"}}}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleList{Items: []rbacv1.ClusterRole{{ObjectMeta: metav1.ObjectMeta{Name: "read-secrets"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}}}}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/prod/roles", "/apis/rbac.authorization.k8s.io/v1/roles":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleList{})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleBindingList{Items: []rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "read-secrets-binding"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "read-secrets"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "prod", Name: "app"}}}}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/prod/rolebindings", "/apis/rbac.authorization.k8s.io/v1/rolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.RoleBindingList{})
		case "/api/v1/secrets", "/api/v1/namespaces/prod/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "legacy-token", Namespace: "prod", Annotations: map[string]string{corev1.ServiceAccountNameKey: "default"}}, Type: corev1.SecretTypeServiceAccountToken}}})
		case "/api/v1/namespaces/kube-public/configmaps/cluster-info":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckServiceAccountsAndTokens(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckServiceAccountsAndTokens returned error: %v", err)
	}
	if len(issues) < 5 {
		t.Fatalf("expected several serviceaccount issues, got %+v", issues)
	}
	if _, err := CheckServiceAccountsAndTokens(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}