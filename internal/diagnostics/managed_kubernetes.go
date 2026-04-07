package diagnostics

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckManagedKubernetes(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	provider := detectClusterProvider(ctx, cs)
	if provider == "" {
		return nil, nil
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
	serviceAccounts, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	storageClasses, err := cs.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		storageClasses = &storagev1.StorageClassList{}
	}
	clusterRoleBindings, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		clusterRoleBindings = &rbacv1.ClusterRoleBindingList{}
	}
	configMaps, err := cs.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		configMaps = &corev1.ConfigMapList{}
	}
	deployments, err := cs.AppsV1().Deployments(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		deployments = &appsv1.DeploymentList{}
	}
	daemonsets, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		daemonsets = &appsv1.DaemonSetList{}
	}

	issues := make([]Issue, 0)
	issues = append(issues, managedControlPlaneExposureIssues(ctx, cs, provider)...)
	issues = append(issues, iamIdentityMappingIssues(provider, configMaps.Items, clusterRoleBindings.Items)...)
	issues = append(issues, managedWorkloadIdentityIssues(provider, pods.Items, serviceAccounts.Items, namespaces)...)
	issues = append(issues, nodeInstanceIdentityIssues(provider, configMaps.Items)...)
	issues = append(issues, metadataExposureIssuesManaged(provider, pods.Items, namespaces)...)
	issues = append(issues, linkedPublicCloudResourceIssues(provider, services.Items, storageClasses.Items, configMaps.Items)...)
	issues = append(issues, managedNodePerimeterIssues(provider, nodes.Items)...)
	issues = append(issues, managedAddonHealthIssues(provider, deployments.Items, daemonsets.Items)...)

	return dedupeIssues(issues), nil
}

func managedControlPlaneExposureIssues(ctx context.Context, cs *kubernetes.Clientset, provider string) []Issue {
	endpoint, source := detectAPIEndpoint(ctx, cs)
	if endpoint == "" {
		return nil
	}
	public, host := isPublicAPIEndpoint(endpoint)
	if !public {
		return nil
	}
	return []Issue{{
		Kind:           "APIServer",
		Severity:       SeverityWarning,
		Category:       "security",
		Check:          "managed-controlplane-public-endpoint",
		Summary:        fmt.Sprintf("managed Kubernetes control plane for %s appears publicly reachable at %s", provider, host),
		Recommendation: "Enable private endpoint access where supported and confirm CIDR allowlists or equivalent provider edge restrictions are in place for the public endpoint.",
		References:     []string{"source=" + source},
	}}
}

func iamIdentityMappingIssues(provider string, configMaps []corev1.ConfigMap, bindings []rbacv1.ClusterRoleBinding) []Issue {
	issues := make([]Issue, 0)
	if provider == "eks/aws" {
		for _, configMap := range configMaps {
			if configMap.Namespace != metav1.NamespaceSystem || configMap.Name != "aws-auth" {
				continue
			}
			data := strings.ToLower(configMap.Data["mapRoles"] + "\n" + configMap.Data["mapUsers"])
			if strings.Contains(data, "system:masters") {
				issues = append(issues, Issue{
					Kind:           "ConfigMap",
					Namespace:      configMap.Namespace,
					Name:           configMap.Name,
					Severity:       SeverityCritical,
					Category:       "security",
					Check:          "eks-iam-mapping-drift",
					Summary:        "aws-auth maps external IAM identities into system:masters",
					Recommendation: "Reduce EKS IAM to Kubernetes mappings to least privilege and avoid broad system:masters membership except for tightly controlled break-glass paths.",
				})
			}
			if strings.Contains(data, "admin") && strings.Contains(data, "userarn") {
				issues = append(issues, Issue{
					Kind:           "ConfigMap",
					Namespace:      configMap.Namespace,
					Name:           configMap.Name,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "eks-iam-mapping-review",
					Summary:        "aws-auth contains static admin-style IAM user mappings",
					Recommendation: "Prefer role-based federation over static IAM user mappings in EKS aws-auth and review stale identity mappings regularly.",
				})
			}
		}
	}
	for _, binding := range bindings {
		if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			text := strings.ToLower(subject.Name)
			if provider == "gke/gce" && containsAny(text, []string{"google", "gke", "gcp", "oidc"}) || provider == "aks/azure" && containsAny(text, []string{"azure", "aad", "aks", "entra"}) {
				issues = append(issues, Issue{
					Kind:           "ClusterRoleBinding",
					Name:           binding.Name,
					Severity:       SeverityWarning,
					Category:       "security",
					Check:          "managed-identity-mapping-review",
					Summary:        fmt.Sprintf("external cloud identity mapping should be reviewed for drift: %s", subject.Name),
					Recommendation: "Review cloud identity groups bound to cluster-admin and confirm they still have correct membership and intended environment scope.",
				})
			}
		}
	}
	return issues
}

func managedWorkloadIdentityIssues(provider string, pods []corev1.Pod, serviceAccounts []corev1.ServiceAccount, namespaces map[string]namespaceMeta) []Issue {
	saIndex := make(map[string]corev1.ServiceAccount, len(serviceAccounts))
	for _, sa := range serviceAccounts {
		saIndex[serviceAccountKey(sa.Namespace, sa.Name)] = sa
	}
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if !podLooksCloudAware(pod) || !isSensitiveWorkload(pod, namespaces[pod.Namespace]) {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		sa := saIndex[serviceAccountKey(pod.Namespace, saName)]
		if hasExpectedWorkloadIdentity(provider, sa) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "managed-workload-identity",
			Summary:        fmt.Sprintf("cloud-aware workload does not show expected %s workload identity configuration", provider),
			Recommendation: "Prefer EKS IRSA, GKE Workload Identity, or AKS Workload Identity over static cloud credentials or node identity inheritance.",
		})
	}
	return issues
}

func nodeInstanceIdentityIssues(provider string, configMaps []corev1.ConfigMap) []Issue {
	if provider != "eks/aws" {
		return []Issue{{
			Kind:           "Node",
			Severity:       SeverityInfo,
			Category:       "security",
			Check:          "managed-node-identity-unverified",
			Summary:        fmt.Sprintf("node instance profile breadth for provider %s cannot be verified from Kubernetes API data alone", provider),
			Recommendation: "Review cloud IAM roles or managed identities attached to node pools and ensure they do not exceed bootstrap and platform-agent needs.",
		}}
	}
	for _, configMap := range configMaps {
		if configMap.Namespace != metav1.NamespaceSystem || configMap.Name != "aws-auth" {
			continue
		}
		data := strings.ToLower(configMap.Data["mapRoles"])
		if strings.Contains(data, "system:masters") {
			return []Issue{{
				Kind:           "ConfigMap",
				Namespace:      configMap.Namespace,
				Name:           configMap.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "managed-node-role-broad",
				Summary:        "node IAM role mapping appears broader than normal node bootstrap permissions",
				Recommendation: "Keep EKS node role mappings limited to system:bootstrappers and system:nodes unless a tightly reviewed exception exists.",
			}}
		}
	}
	return nil
}

func metadataExposureIssuesManaged(provider string, pods []corev1.Pod, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		fields := []string{pod.Name, pod.Namespace}
		for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			fields = append(fields, container.Name, container.Image)
			fields = append(fields, container.Command...)
			fields = append(fields, container.Args...)
			for _, env := range container.Env {
				fields = append(fields, env.Name+"="+env.Value)
			}
		}
		if !pod.Spec.HostNetwork && !containsAny(strings.ToLower(strings.Join(fields, " ")), []string{"169.254.169.254", "metadata.google.internal", "instance metadata", "imds"}) {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[pod.Namespace]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "managed-metadata-exposure",
			Summary:        fmt.Sprintf("workload may reach cloud instance metadata from %s", provider),
			Recommendation: "Block IMDS access from ordinary pods, avoid hostNetwork where possible, and prefer workload identity over instance-profile credential inheritance.",
		})
	}
	return issues
}

func linkedPublicCloudResourceIssues(provider string, services []corev1.Service, classes []storagev1.StorageClass, configMaps []corev1.ConfigMap) []Issue {
	issues := make([]Issue, 0)
	for _, service := range services {
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer && !serviceHasAllowlist(service) {
			issues = append(issues, Issue{
				Kind:           "Service",
				Namespace:      service.Namespace,
				Name:           service.Name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "managed-public-loadbalancer",
				Summary:        fmt.Sprintf("public load balancer linked to a %s cluster lacks obvious source restrictions", provider),
				Recommendation: "Restrict public load balancers with source allowlists, internal schemes, or private ingress patterns where possible.",
			})
		}
	}
	for _, class := range classes {
		if storageTargetLooksPublic(class.Parameters, class.Annotations) {
			issues = append(issues, Issue{
				Kind:           "StorageClass",
				Name:           class.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "managed-public-storage-target",
				Summary:        fmt.Sprintf("storage class in %s cluster references a public-like storage target", provider),
				Recommendation: "Ensure cloud buckets, snapshots, and disk export targets linked to the cluster are private and tightly scoped.",
			})
		}
	}
	for _, configMap := range configMaps {
		text := strings.ToLower(strings.Join(mapValues(configMap.Data), " "))
		if containsAny(text, []string{"s3://", "gs://", "blob.core.windows.net"}) && containsAny(text, []string{"public", "allusers", "anonymous", "public-read"}) {
			issues = append(issues, Issue{
				Kind:           "ConfigMap",
				Namespace:      configMap.Namespace,
				Name:           configMap.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "managed-public-bucket-link",
				Summary:        "cluster configuration references publicly accessible bucket or blob storage",
				Recommendation: "Review backup, artifact, and export storage targets so they are private and do not expose cluster-linked data publicly.",
			})
		}
	}
	return issues
}

func managedNodePerimeterIssues(provider string, nodes []corev1.Node) []Issue {
	public := 0
	for _, node := range nodes {
		if nodeAddress(node, corev1.NodeExternalIP) != "" {
			public++
		}
	}
	if public == 0 {
		return nil
	}
	return []Issue{{
		Kind:           "Node",
		Severity:       SeverityWarning,
		Category:       "security",
		Check:          "managed-node-perimeter",
		Summary:        fmt.Sprintf("%d nodes in %s cluster have public IP addresses; cloud firewall/security-group posture should be reviewed", public, provider),
		Recommendation: "Verify node pool security groups, firewall rules, and instance access paths so kubelet, SSH, and node-agent ports are not broadly reachable.",
	}}
}

func managedAddonHealthIssues(provider string, deployments []appsv1.Deployment, daemonsets []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	images := map[string]string{}
	for _, deployment := range deployments {
		for _, container := range deployment.Spec.Template.Spec.Containers {
			images[deployment.Name] = container.Image
		}
	}
	for _, daemonset := range daemonsets {
		for _, container := range daemonset.Spec.Template.Spec.Containers {
			images[daemonset.Name] = container.Image
		}
	}
	required := requiredManagedAddons(provider)
	for _, addon := range required {
		image, ok := images[addon]
		if !ok {
			issues = append(issues, Issue{
				Kind:           "ControlPlane",
				Namespace:      metav1.NamespaceSystem,
				Name:           addon,
				Severity:       SeverityInfo,
				Category:       "security",
				Check:          "managed-addon-missing",
				Summary:        fmt.Sprintf("expected managed add-on %s was not observed in kube-system for provider %s", addon, provider),
				Recommendation: "Review whether this provider add-on is intentionally absent, renamed, or managed outside the cluster API view.",
			})
			continue
		}
		if strings.HasSuffix(strings.ToLower(image), ":latest") || !strings.Contains(image, ":") {
			issues = append(issues, Issue{
				Kind:           "ControlPlane",
				Namespace:      metav1.NamespaceSystem,
				Name:           addon,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "managed-addon-version",
				Summary:        fmt.Sprintf("managed add-on %s uses an unpinned image tag (%s)", addon, image),
				Recommendation: "Pin managed add-ons to explicit versions and review provider-supported upgrade paths regularly.",
			})
		}
	}
	return issues
}

func hasExpectedWorkloadIdentity(provider string, sa corev1.ServiceAccount) bool {
	switch provider {
	case "eks/aws":
		return strings.TrimSpace(sa.Annotations["eks.amazonaws.com/role-arn"]) != ""
	case "gke/gce":
		return strings.TrimSpace(sa.Annotations["iam.gke.io/gcp-service-account"]) != ""
	case "aks/azure":
		return strings.TrimSpace(sa.Annotations["azure.workload.identity/client-id"]) != ""
	default:
		return false
	}
}

func podLooksCloudAware(pod corev1.Pod) bool {
	fields := []string{pod.Name}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		fields = append(fields, container.Name, container.Image)
		fields = append(fields, container.Command...)
		fields = append(fields, container.Args...)
		for _, env := range container.Env {
			fields = append(fields, env.Name+"="+env.Value)
		}
	}
	text := strings.ToLower(strings.Join(fields, " "))
	return containsAny(text, []string{"aws", "s3", "sts", "gcp", "google", "gcs", "azure", "blob", "cosmos", "kms", "keyvault", "pubsub", "sqs", "sns"})
}

func mapValues(values map[string]string) []string {
	items := make([]string, 0, len(values))
	for _, value := range values {
		items = append(items, value)
	}
	return items
}

func requiredManagedAddons(provider string) []string {
	switch provider {
	case "eks/aws":
		return []string{"aws-node", "coredns", "kube-proxy"}
	case "gke/gce":
		return []string{"coredns", "kube-proxy"}
	case "aks/azure":
		return []string{"coredns", "kube-proxy"}
	default:
		return nil
	}
}
