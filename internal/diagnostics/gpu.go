package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type gpuResourceInventory struct {
	capacity    []string
	allocatable []string
}

func CheckGPU(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}

	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	nodes, err := listNodesCached(ctx, cs)
	if err != nil {
		return nil, err
	}
	pods, err := listPodsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	events, err := listEventsCached(ctx, cs, ns)
	if err != nil {
		return nil, err
	}
	daemonsets, err := listDaemonSetsCached(ctx, cs, metav1.NamespaceAll)
	if err != nil {
		return nil, err
	}
	configMaps, err := listConfigMapsCached(ctx, cs, metav1.NamespaceAll)
	if err != nil {
		configMaps = nil
	}

	resourceByNode := map[string]gpuResourceInventory{}
	gpuNodes := make([]corev1.Node, 0)
	for _, node := range nodes {
		inventory := gpuInventoryForResources(node.Status.Capacity, node.Status.Allocatable)
		resourceByNode[node.Name] = inventory
		if len(inventory.capacity) > 0 || len(inventory.allocatable) > 0 || nodeLooksLikeGPUNode(node) {
			gpuNodes = append(gpuNodes, node)
		}
	}

	issues := make([]Issue, 0)
	issues = append(issues, gpuNodeInventoryIssues(gpuNodes, resourceByNode)...)
	issues = append(issues, gpuOperatorIssues(gpuNodes, daemonsets)...)
	issues = append(issues, gpuPodSpecIssues(pods, gpuNodes, resourceByNode)...)
	issues = append(issues, gpuSchedulingEventIssues(events)...)
	issues = append(issues, gpuRuntimeMismatchIssues(pods, events)...)
	issues = append(issues, gpuObservabilityIssues(pods, daemonsets, configMaps, dyn)...)
	issues = append(issues, gpuOversubscriptionIssues(gpuNodes, pods, resourceByNode)...)

	return dedupeIssues(issues), nil
}

func gpuNodeInventoryIssues(nodes []corev1.Node, inventory map[string]gpuResourceInventory) []Issue {
	issues := make([]Issue, 0)
	for _, node := range nodes {
		resources := inventory[node.Name]
		if len(resources.capacity) == 0 && nodeLooksLikeGPUNode(node) {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityCritical,
				Category:       "workloads",
				Check:          "gpu-node-resource-missing",
				Summary:        "node looks like a GPU node but does not advertise nvidia.com GPU resources in capacity/allocatable",
				Recommendation: "Verify the NVIDIA device plugin, kubelet device plugin registration, and node driver installation so GPU resources appear as nvidia.com/gpu or nvidia.com/mig-*.",
			})
		}
		if len(resources.capacity) > 0 && len(resources.allocatable) == 0 {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityCritical,
				Category:       "workloads",
				Check:          "gpu-node-allocatable-missing",
				Summary:        fmt.Sprintf("node advertises GPU capacity but no allocatable GPU resources: %s", strings.Join(resources.capacity, ", ")),
				Recommendation: "Check kubelet registration, device plugin health, and whether the node is still initializing GPU devices before scheduling AI workloads.",
			})
		}
		for _, resourceName := range resources.capacity {
			if !containsString(resources.allocatable, resourceName) {
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Category:       "workloads",
					Check:          "gpu-node-resource-mismatch",
					Summary:        fmt.Sprintf("node capacity includes %s but allocatable does not", resourceName),
					Recommendation: "Inspect kubelet and device plugin logs; mismatched capacity/allocatable usually means the GPU inventory is partially registered or unhealthy.",
				})
			}
		}
	}
	return issues
}

func gpuOperatorIssues(nodes []corev1.Node, daemonsets []appsv1.DaemonSet) []Issue {
	if len(nodes) == 0 {
		return nil
	}

	issues := make([]Issue, 0)
	pluginDetected := false
	for _, daemonset := range daemonsets {
		classification := classifyGPUDaemonSet(daemonset)
		if classification == "" {
			continue
		}
		if classification == "device-plugin" {
			pluginDetected = true
		}
		desired := daemonset.Status.DesiredNumberScheduled
		available := daemonset.Status.NumberAvailable
		if desired > available {
			severity := SeverityWarning
			if classification == "device-plugin" {
				severity = SeverityCritical
			}
			issues = append(issues, Issue{
				Kind:           "DaemonSet",
				Namespace:      daemonset.Namespace,
				Name:           daemonset.Name,
				Severity:       severity,
				Category:       "workloads",
				Check:          "gpu-daemonset-unavailable",
				Summary:        fmt.Sprintf("GPU %s daemonset is not fully available (%d/%d)", classification, available, desired),
				Recommendation: "Stabilize the NVIDIA GPU Operator/device plugin rollout before relying on GPU scheduling; otherwise nodes may exist without usable GPU resources.",
			})
		}
	}
	if !pluginDetected {
		issues = append(issues, Issue{
			Kind:           "DaemonSet",
			Namespace:      metav1.NamespaceAll,
			Name:           "nvidia-device-plugin",
			Severity:       SeverityCritical,
			Category:       "workloads",
			Check:          "gpu-device-plugin-missing",
			Summary:        "GPU nodes exist but no obvious NVIDIA device plugin daemonset was detected",
			Recommendation: "Deploy the NVIDIA device plugin or GPU Operator; without it, the scheduler can see nodes but not nvidia.com GPU resources.",
		})
	}
	return issues
}

func gpuPodSpecIssues(pods []corev1.Pod, nodes []corev1.Node, inventory map[string]gpuResourceInventory) []Issue {
	issues := make([]Issue, 0)
	gpuTaints := gpuNodeTaints(nodes)
	clusterResources := clusterGPUResourceNames(inventory)
	for _, pod := range pods {
		gpuResources := podGPUResourceRequests(pod)
		likelyGPU := len(gpuResources) > 0 || podLooksLikeGPUWorkload(pod)
		if !likelyGPU {
			continue
		}

		if len(gpuResources) == 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "gpu-pod-missing-limits",
				Summary:        "workload looks GPU-oriented but does not declare nvidia.com GPU limits",
				Recommendation: "Set container limits for nvidia.com/gpu or the required nvidia.com/mig-* profile so the scheduler places this workload on GPU nodes.",
			})
		}

		for _, container := range allContainersForPod(pod) {
			issues = append(issues, containerGPUResourceIssues(pod, container)...)
		}

		if len(gpuTaints) > 0 && !podToleratesAnyTaint(pod.Spec.Tolerations, gpuTaints) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "gpu-pod-untolerated-taint",
				Summary:        fmt.Sprintf("GPU-oriented workload does not tolerate GPU node taints: %s", strings.Join(gpuTaintStrings(gpuTaints), ", ")),
				Recommendation: "Add tolerations for dedicated GPU taints such as dedicated=gpu:NoSchedule, or move the workload to untainted accelerator nodes.",
			})
		}

		if len(gpuResources) > 0 && requestsUnavailableGPUProfile(gpuResources, clusterResources) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityCritical,
				Category:       "workloads",
				Check:          "gpu-profile-unavailable",
				Summary:        fmt.Sprintf("workload requests GPU resources not exposed by current nodes: %s", strings.Join(sortedResourceKeys(gpuResources), ", ")),
				Recommendation: "Align pod limits with the GPU profiles actually advertised by nodes, especially when MIG or shared/time-sliced resources are enabled.",
			})
		}
	}
	return issues
}

func gpuSchedulingEventIssues(events []corev1.Event) []Issue {
	issues := make([]Issue, 0)
	for _, event := range events {
		text := strings.ToLower(event.Reason + " " + event.Message)
		if !containsAny(text, []string{"nvidia.com/gpu", "untolerated taint", "node affinity", "didn't match pod affinity", "didn't match node selector", "insufficient"}) {
			continue
		}
		if !containsAny(text, []string{"nvidia.com/gpu", "gpu", "taint", "node affinity", "node selector"}) {
			continue
		}
		severity := SeverityWarning
		if containsAny(text, []string{"insufficient nvidia.com/gpu", "0/", "untolerated taint"}) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           event.InvolvedObject.Kind,
			Namespace:      event.Namespace,
			Name:           event.InvolvedObject.Name,
			Severity:       severity,
			Category:       "workloads",
			Check:          "gpu-scheduling-event",
			Summary:        fmt.Sprintf("scheduler reported GPU placement issue: %s - %s", event.Reason, truncateString(event.Message, 160)),
			Recommendation: "Review GPU limits, taints/tolerations, and node affinity; common causes are insufficient nvidia.com/gpu, missing tolerations, or requesting the wrong MIG profile.",
		})
	}
	return issues
}

func gpuRuntimeMismatchIssues(pods []corev1.Pod, events []corev1.Event) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		if len(podGPUResourceRequests(pod)) == 0 && !podLooksLikeGPUWorkload(pod) {
			continue
		}
		for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
			if status.State.Waiting == nil {
				continue
			}
			message := strings.ToLower(status.State.Waiting.Reason + " " + status.State.Waiting.Message)
			if !containsAny(message, gpuRuntimeErrorMarkers()) {
				continue
			}
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityCritical,
				Category:       "workloads",
				Check:          "gpu-runtime-mismatch",
				Summary:        fmt.Sprintf("container %s failed with GPU runtime or driver mismatch indicators", status.Name),
				Recommendation: "Check NVIDIA driver/CUDA compatibility, nvidia-container-runtime configuration, and whether the node image matches the workload's CUDA requirements.",
			})
		}
	}
	for _, event := range events {
		text := strings.ToLower(event.Reason + " " + event.Message)
		if !containsAny(text, gpuRuntimeErrorMarkers()) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           event.InvolvedObject.Kind,
			Namespace:      event.Namespace,
			Name:           event.InvolvedObject.Name,
			Severity:       SeverityCritical,
			Category:       "workloads",
			Check:          "gpu-runtime-mismatch",
			Summary:        fmt.Sprintf("runtime reported GPU driver/CUDA failure: %s", truncateString(event.Message, 160)),
			Recommendation: "Check the host driver, CUDA compatibility, container runtime hooks, and NVIDIA runtime classes after the pod was scheduled.",
		})
	}
	return issues
}

func gpuObservabilityIssues(pods []corev1.Pod, daemonsets []appsv1.DaemonSet, configMaps []corev1.ConfigMap, dyn dynamic.Interface) []Issue {
	issues := make([]Issue, 0)
	hasDCGM := workloadSetContains(pods, daemonsets, []string{"dcgm-exporter", "nvidia-dcgm-exporter"})
	if !hasDCGM {
		issues = append(issues, Issue{
			Kind:           "DaemonSet",
			Name:           "dcgm-exporter",
			Severity:       SeverityWarning,
			Category:       "workloads",
			Check:          "gpu-observability-missing",
			Summary:        "no obvious dcgm-exporter or equivalent GPU telemetry collector was detected",
			Recommendation: "Deploy dcgm-exporter or an equivalent collector so GPU utilization, memory pressure, ECC, and XID failures are visible.",
		})
	}

	ruleCorpus := strings.ToLower(collectAlertRuleCorpus(context.Background(), dyn, metav1.NamespaceAll, configMaps))
	if hasDCGM && !containsAny(ruleCorpus, []string{"dcgm_fi_dev_gpu_util", "gpu_util", "gpu_memory", "fb_used", "xid", "dcgm"}) {
		issues = append(issues, Issue{
			Kind:           "ControlPlane",
			Name:           "monitoring",
			Severity:       SeverityInfo,
			Category:       "workloads",
			Check:          "gpu-alerting-missing",
			Summary:        "GPU telemetry seems present but no obvious alert coverage for utilization, memory, or XID errors was detected",
			Recommendation: "Add GPU alerts for utilization saturation, memory exhaustion, and NVIDIA XID faults so AI/LLM nodes fail loudly instead of silently degrading.",
		})
	}
	return issues
}

func gpuOversubscriptionIssues(nodes []corev1.Node, pods []corev1.Pod, inventory map[string]gpuResourceInventory) []Issue {
	issues := make([]Issue, 0)
	for _, node := range nodes {
		resources := inventory[node.Name]
		shared := node.Labels["nvidia.com/gpu.sharing-strategy"]
		migStrategy := node.Labels["nvidia.com/mig.strategy"]
		hasFullGPU := containsString(resources.capacity, "nvidia.com/gpu") || containsString(resources.allocatable, "nvidia.com/gpu")
		hasMIG := containsPrefix(resources.capacity, "nvidia.com/mig-") || containsPrefix(resources.allocatable, "nvidia.com/mig-")
		if shared != "" {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityInfo,
				Category:       "workloads",
				Check:          "gpu-sharing-mode",
				Summary:        fmt.Sprintf("node uses GPU sharing strategy %q", shared),
				Recommendation: "Validate that time-slicing or shared GPU mode still matches the latency and isolation expectations of your AI workloads.",
			})
		}
		if migStrategy != "" && hasMIG {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityInfo,
				Category:       "workloads",
				Check:          "gpu-mig-mode",
				Summary:        fmt.Sprintf("node exposes MIG resources with strategy %q", migStrategy),
				Recommendation: "Ensure workloads request the exact nvidia.com/mig-* profile they need; MIG nodes can look healthy while still lacking the requested slice size.",
			})
		}
		if hasFullGPU && hasMIG {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "gpu-mixed-advertisement",
				Summary:        "node advertises both full GPU and MIG resources",
				Recommendation: "Double-check scheduling expectations and quotas; mixed full-GPU and MIG advertising can confuse workload placement and capacity planning.",
			})
		}
	}

	clusterResources := clusterGPUResourceNames(inventory)
	for _, pod := range pods {
		requested := podGPUResourceRequests(pod)
		if len(requested) == 0 {
			continue
		}
		if requestsUnavailableGPUProfile(requested, clusterResources) {
			continue
		}
		if requestsFullGPUOnMIGOnlyCluster(requested, clusterResources) {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityCritical,
				Category:       "workloads",
				Check:          "gpu-oversubscription-profile-mismatch",
				Summary:        "workload requests full GPUs but the cluster only exposes MIG-style GPU slices",
				Recommendation: "Request the exact MIG profile or provide nodes exposing full nvidia.com/gpu resources; otherwise scheduler success and usable capacity will diverge.",
			})
		}
	}
	return issues
}

func gpuInventoryForResources(capacity, allocatable corev1.ResourceList) gpuResourceInventory {
	return gpuResourceInventory{
		capacity:    gpuResourceNames(capacity),
		allocatable: gpuResourceNames(allocatable),
	}
}

func gpuResourceNames(resources corev1.ResourceList) []string {
	names := make([]string, 0)
	for name, quantity := range resources {
		resourceName := string(name)
		if !isGPUResourceName(resourceName) {
			continue
		}
		if quantity.Sign() <= 0 {
			continue
		}
		names = append(names, resourceName)
	}
	sort.Strings(names)
	return names
}

func isGPUResourceName(name string) bool {
	return name == "nvidia.com/gpu" || strings.HasPrefix(name, "nvidia.com/mig-")
}

func nodeLooksLikeGPUNode(node corev1.Node) bool {
	textParts := make([]string, 0, len(node.Labels)+len(node.Spec.Taints))
	for key, value := range node.Labels {
		textParts = append(textParts, key+"="+value)
	}
	for _, taint := range node.Spec.Taints {
		textParts = append(textParts, taint.Key+"="+taint.Value)
	}
	text := strings.ToLower(strings.Join(textParts, " "))
	return containsAny(text, []string{"nvidia", "gpu", "accelerator", "mig", "tesla", "l4", "a100", "h100", "dedicated=gpu"})
}

func classifyGPUDaemonSet(daemonset appsv1.DaemonSet) string {
	parts := []string{daemonset.Namespace, daemonset.Name}
	for _, container := range daemonset.Spec.Template.Spec.Containers {
		parts = append(parts, container.Name, container.Image)
	}
	text := strings.ToLower(strings.Join(parts, " "))
	switch {
	case containsAny(text, []string{"k8s-device-plugin", "nvidia-device-plugin", "device-plugin"}):
		return "device-plugin"
	case containsAny(text, []string{"gpu-operator", "nvidia-operator-validator", "gpu-feature-discovery"}):
		return "operator"
	case containsAny(text, []string{"dcgm-exporter", "nvidia-dcgm-exporter"}):
		return "telemetry"
	default:
		return ""
	}
}

func podGPUResourceRequests(pod corev1.Pod) map[string]resource.Quantity {
	resources := map[string]resource.Quantity{}
	for _, container := range allContainersForPod(pod) {
		for name, quantity := range container.Resources.Limits {
			resourceName := string(name)
			if isGPUResourceName(resourceName) && quantity.Sign() > 0 {
				resources[resourceName] = quantity.DeepCopy()
			}
		}
		for name, quantity := range container.Resources.Requests {
			resourceName := string(name)
			if isGPUResourceName(resourceName) && quantity.Sign() > 0 {
				resources[resourceName] = quantity.DeepCopy()
			}
		}
	}
	return resources
}

func allContainersForPod(pod corev1.Pod) []corev1.Container {
	containers := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	containers = append(containers, pod.Spec.InitContainers...)
	containers = append(containers, pod.Spec.Containers...)
	return containers
}

func podLooksLikeGPUWorkload(pod corev1.Pod) bool {
	fields := []string{pod.Name}
	for key, value := range pod.Labels {
		fields = append(fields, key+"="+value)
	}
	for key, value := range pod.Spec.NodeSelector {
		fields = append(fields, key+"="+value)
	}
	for _, container := range allContainersForPod(pod) {
		fields = append(fields, container.Name, container.Image)
		fields = append(fields, container.Command...)
		fields = append(fields, container.Args...)
		for _, env := range container.Env {
			fields = append(fields, env.Name+"="+env.Value)
		}
	}
	text := strings.ToLower(strings.Join(fields, " "))
	return containsAny(text, []string{"cuda", "nvidia", "triton", "vllm", "ollama", "text-generation-inference", "tensorflow", "pytorch", "torch", "llm", "inference", "gpu"})
}

func containerGPUResourceIssues(pod corev1.Pod, container corev1.Container) []Issue {
	issues := make([]Issue, 0)
	for name, limit := range container.Resources.Limits {
		resourceName := string(name)
		if !isGPUResourceName(resourceName) || limit.Sign() <= 0 {
			continue
		}
		if request, ok := container.Resources.Requests[name]; ok && request.Sign() > 0 && request.Cmp(limit) != 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "gpu-resource-request-mismatch",
				Summary:        fmt.Sprintf("container %s sets %s request=%s and limit=%s", container.Name, resourceName, request.String(), limit.String()),
				Recommendation: "Use matching request and limit values for extended GPU resources so scheduling semantics stay predictable.",
			})
		}
	}
	for name, request := range container.Resources.Requests {
		resourceName := string(name)
		if !isGPUResourceName(resourceName) || request.Sign() <= 0 {
			continue
		}
		if limit, ok := container.Resources.Limits[name]; !ok || limit.Sign() <= 0 {
			issues = append(issues, Issue{
				Kind:           "Pod",
				Namespace:      pod.Namespace,
				Name:           pod.Name,
				Severity:       SeverityWarning,
				Category:       "workloads",
				Check:          "gpu-resource-limit-missing",
				Summary:        fmt.Sprintf("container %s requests %s but does not declare a matching limit", container.Name, resourceName),
				Recommendation: "Declare GPU limits explicitly; Kubernetes extended resources should be expressed via limits so placement onto GPU nodes is deterministic.",
			})
		}
	}
	return issues
}

func gpuNodeTaints(nodes []corev1.Node) []corev1.Taint {
	collected := make([]corev1.Taint, 0)
	seen := map[string]struct{}{}
	for _, node := range nodes {
		for _, taint := range node.Spec.Taints {
			if taint.Effect != corev1.TaintEffectNoSchedule && taint.Effect != corev1.TaintEffectNoExecute {
				continue
			}
			text := strings.ToLower(taint.Key + "=" + taint.Value)
			if !containsAny(text, []string{"gpu", "nvidia", "accelerator", "dedicated=gpu"}) {
				continue
			}
			key := taint.Key + "|" + taint.Value + "|" + string(taint.Effect)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			collected = append(collected, taint)
		}
	}
	return collected
}

func podToleratesAnyTaint(tolerations []corev1.Toleration, taints []corev1.Taint) bool {
	for _, taint := range taints {
		if toleratesTaint(tolerations, taint) {
			return true
		}
	}
	return false
}

func gpuTaintStrings(taints []corev1.Taint) []string {
	values := make([]string, 0, len(taints))
	for _, taint := range taints {
		values = append(values, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
	}
	sort.Strings(values)
	return values
}

func clusterGPUResourceNames(inventory map[string]gpuResourceInventory) []string {
	set := map[string]struct{}{}
	for _, item := range inventory {
		for _, name := range item.capacity {
			set[name] = struct{}{}
		}
		for _, name := range item.allocatable {
			set[name] = struct{}{}
		}
	}
	return sortedSetKeys(set)
}

func requestsUnavailableGPUProfile(requested map[string]resource.Quantity, available []string) bool {
	if len(requested) == 0 {
		return false
	}
	availableSet := map[string]struct{}{}
	for _, name := range available {
		availableSet[name] = struct{}{}
	}
	for name := range requested {
		if _, ok := availableSet[name]; !ok {
			return true
		}
	}
	return false
}

func requestsFullGPUOnMIGOnlyCluster(requested map[string]resource.Quantity, available []string) bool {
	hasFull := false
	hasMIG := false
	for name := range requested {
		if name == "nvidia.com/gpu" {
			hasFull = true
		}
		if strings.HasPrefix(name, "nvidia.com/mig-") {
			hasMIG = true
		}
	}
	if !hasFull || hasMIG {
		return false
	}
	for _, name := range available {
		if name == "nvidia.com/gpu" {
			return false
		}
	}
	for _, name := range available {
		if strings.HasPrefix(name, "nvidia.com/mig-") {
			return true
		}
	}
	return false
}

func gpuRuntimeErrorMarkers() []string {
	return []string{
		"nvidia-container-runtime",
		"cuda driver version is insufficient",
		"failed to initialize nvml",
		"libnvidia-ml.so",
		"could not select device driver",
		"no cuda-capable device is detected",
		"xid",
		"failed to create pod sandbox",
	}
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func sortedResourceKeys(values map[string]resource.Quantity) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSetKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
