package diagnostics

import (
	"context"
	"net/http"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGPUHelpers(t *testing.T) {
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "gpu-a", Labels: map[string]string{"nvidia.com/gpu.present": "true", "nvidia.com/mig.strategy": "mixed", "nvidia.com/gpu.sharing-strategy": "time-slicing"}},
		Spec:       corev1.NodeSpec{Taints: []corev1.Taint{{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("2"), corev1.ResourceName("nvidia.com/mig-1g.10gb"): resource.MustParse("1")},
			Allocatable: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("2")},
		},
	}
	inventory := gpuInventoryForResources(node.Status.Capacity, node.Status.Allocatable)
	if !nodeLooksLikeGPUNode(node) || !containsString(inventory.capacity, "nvidia.com/gpu") || !containsPrefix(inventory.capacity, "nvidia.com/mig-") {
		t.Fatal("expected GPU helper inventory to detect full GPU and MIG resources")
	}
	if classifyGPUDaemonSet(appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "nvidia-device-plugin", Namespace: "gpu-system"}}) != "device-plugin" {
		t.Fatal("expected device plugin classification")
	}
	if len(gpuNodeTaints([]corev1.Node{node})) != 1 {
		t.Fatal("expected GPU taint discovery")
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "llm", Namespace: "prod", Labels: map[string]string{"app": "vllm"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "model",
			Image: "nvcr.io/nvidia/tritonserver:24.01-py3",
			Resources: corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1")},
				Requests: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("2")},
			},
		}}},
	}
	if !podLooksLikeGPUWorkload(pod) || !requestsFullGPUOnMIGOnlyCluster(podGPUResourceRequests(pod), []string{"nvidia.com/mig-1g.10gb"}) {
		t.Fatal("expected GPU workload heuristics to match")
	}
	if len(containerGPUResourceIssues(pod, pod.Spec.Containers[0])) == 0 {
		t.Fatal("expected GPU request/limit mismatch issue")
	}
}

func TestCheckGPU(t *testing.T) {
	ctx := context.Background()

	gpuNode := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gpu-a",
			Labels: map[string]string{
				"nvidia.com/gpu.present":          "true",
				"nvidia.com/mig.strategy":         "mixed",
				"nvidia.com/gpu.sharing-strategy": "time-slicing",
			},
		},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceName("nvidia.com/gpu"):       resource.MustParse("4"),
				corev1.ResourceName("nvidia.com/mig-1g.10gb"): resource.MustParse("7"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceName("nvidia.com/mig-1g.10gb"): resource.MustParse("7"),
			},
		},
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "llm", Namespace: "prod", Labels: map[string]string{"app": "vllm"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "model",
			Image: "nvcr.io/nvidia/tritonserver:24.01-py3",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1")},
			},
		}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "model",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CreateContainerError",
					Message: "nvidia-container-runtime hook failed: CUDA driver version is insufficient for CUDA runtime version",
				}},
			}},
		},
	}

	events := []corev1.Event{{
		ObjectMeta: metav1.ObjectMeta{Name: "llm.1", Namespace: "prod", CreationTimestamp: metav1.Now()},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "llm"},
		Reason:         "FailedScheduling",
		Message:        "0/1 nodes are available: 1 Insufficient nvidia.com/gpu, 1 node(s) had untolerated taint {dedicated: gpu}.",
		Type:           "Warning",
		LastTimestamp:  metav1.Now(),
	}, {
		ObjectMeta: metav1.ObjectMeta{Name: "llm.2", Namespace: "prod", CreationTimestamp: metav1.Now()},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "llm"},
		Reason:         "Failed",
		Message:        "failed to create pod sandbox: could not select device driver \"\" with capabilities: [[gpu]]",
		Type:           "Warning",
		LastTimestamp:  metav1.Now(),
	}}

	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{gpuNode}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/api/v1/namespaces/prod/events":
			writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: events})
		case "/apis/apps/v1/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{{
				ObjectMeta: metav1.ObjectMeta{Name: "nvidia-device-plugin-daemonset", Namespace: "gpu-system"},
				Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "plugin", Image: "nvcr.io/nvidia/k8s-device-plugin:v0.16.1"}}}}},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberAvailable: 0},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "gpu-operator", Namespace: "gpu-system"},
				Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "operator", Image: "nvcr.io/nvidia/gpu-operator:latest"}}}}},
				Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberAvailable: 0},
			}}})
		case "/api/v1/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/api/v1/configmaps":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ConfigMapList{})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckGPU(ctx, cs, nil, "prod")
	if err != nil {
		t.Fatalf("CheckGPU returned error: %v", err)
	}
	if len(issues) < 8 {
		t.Fatalf("expected multiple GPU issues, got %+v", issues)
	}
	checks := map[string]bool{}
	for _, issue := range issues {
		checks[issue.Check] = true
	}
	for _, expected := range []string{"gpu-node-resource-mismatch", "gpu-daemonset-unavailable", "gpu-pod-untolerated-taint", "gpu-scheduling-event", "gpu-runtime-mismatch", "gpu-observability-missing", "gpu-mig-mode", "gpu-sharing-mode"} {
		if !checks[expected] {
			t.Fatalf("expected check %q in %+v", expected, issues)
		}
	}

	if _, err := CheckGPU(ctx, nil, nil, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}