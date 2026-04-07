package diagnostics

import (
	"context"
	"net/http"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestManagedKubernetesHelpers(t *testing.T) {
	ns := map[string]namespaceMeta{"prod": {name: "prod", labels: map[string]string{"environment": "production"}}}
	sa := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod", Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn:aws:iam::1:role/app"}}}
	if !hasExpectedWorkloadIdentity("eks/aws", sa) || !podLooksCloudAware(corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "aws-sync"}}) {
		t.Fatal("expected workload identity helpers to match")
	}
	if len(mapValues(map[string]string{"a": "1", "b": "2"})) != 2 || len(requiredManagedAddons("eks/aws")) != 3 {
		t.Fatal("unexpected managed helper values")
	}
	if len(iamIdentityMappingIssues("eks/aws", []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "aws-auth", Namespace: metav1.NamespaceSystem}, Data: map[string]string{"mapRoles": "system:masters", "mapUsers": "admin userarn"}}}, []rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "gke-admin"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "gke-admin@example.com"}}}})) == 0 {
		t.Fatal("expected iam identity mapping issues")
	}
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "aws-job", Namespace: "prod"}, Spec: corev1.PodSpec{ServiceAccountName: "app", HostNetwork: true}}}
	if len(managedWorkloadIdentityIssues("eks/aws", pods, []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}}}, ns)) == 0 {
		t.Fatal("expected managed workload identity issue")
	}
	if len(nodeInstanceIdentityIssues("eks/aws", []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "aws-auth", Namespace: metav1.NamespaceSystem}, Data: map[string]string{"mapRoles": "system:masters"}}})) == 0 {
		t.Fatal("expected node instance identity issue")
	}
	if len(metadataExposureIssuesManaged("eks/aws", pods, ns)) == 0 {
		t.Fatal("expected metadata exposure issue")
	}
	if len(linkedPublicCloudResourceIssues("eks/aws", []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "public-lb", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}}, []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "public-storage"}, Parameters: map[string]string{"bucket": "public-s3"}}}, []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "prod"}, Data: map[string]string{"target": "s3://public-bucket public-read"}}})) == 0 {
		t.Fatal("expected linked public cloud resource issues")
	}
	if len(managedNodePerimeterIssues("eks/aws", []corev1.Node{{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "1.2.3.4"}}}}})) == 0 {
		t.Fatal("expected node perimeter issue")
	}
	if len(managedAddonHealthIssues("eks/aws", []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "coredns"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "coredns:latest"}}}}}}}, []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "aws-node"}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "aws-node:latest"}}}}}}})) == 0 {
		t.Fatal("expected managed addon health issues")
	}
}

func TestCheckManagedKubernetes(t *testing.T) {
	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "aws-job", Namespace: "prod"}, Spec: corev1.PodSpec{ServiceAccountName: "default", HostNetwork: true}}}})
		case "/api/v1/namespaces/prod/serviceaccounts":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceAccountList{Items: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}}}})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: corev1.NodeSpec{ProviderID: "aws:///zone/i-123"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "1.2.3.4"}}}}}})
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "public-lb", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}}})
		case "/apis/storage.k8s.io/v1/storageclasses":
			writeJSONResponse(t, w, http.StatusOK, &storagev1.StorageClassList{Items: []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "public-storage"}, Parameters: map[string]string{"bucket": "public-s3"}}}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			writeJSONResponse(t, w, http.StatusOK, &rbacv1.ClusterRoleBindingList{Items: []rbacv1.ClusterRoleBinding{{ObjectMeta: metav1.ObjectMeta{Name: "gke-admin"}, RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, Subjects: []rbacv1.Subject{{Kind: "Group", Name: "gke-admins"}}}}})
		case "/api/v1/configmaps":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{Items: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "aws-auth", Namespace: metav1.NamespaceSystem}, Data: map[string]string{"mapRoles": "system:masters", "mapUsers": "admin userarn"}}, {ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "prod"}, Data: map[string]string{"target": "s3://public-bucket public-read"}}}})
		case "/apis/apps/v1/namespaces/kube-system/deployments":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "coredns", Namespace: metav1.NamespaceSystem}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "coredns:latest"}}}}}}}})
		case "/apis/apps/v1/namespaces/kube-system/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "aws-node", Namespace: metav1.NamespaceSystem}, Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "aws-node:latest"}}}}}}}})
		case "/api/v1/namespaces/kube-public/configmaps/cluster-info":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"}, Data: map[string]string{"kubeconfig": string(kubeconfigBytes(t, "https://35.1.2.3:6443", "reader", false))}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckManagedKubernetes(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckManagedKubernetes returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected several managed kubernetes issues, got %+v", issues)
	}
	if _, err := CheckManagedKubernetes(ctx, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
