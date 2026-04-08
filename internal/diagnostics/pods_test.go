package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodHelpersAndCheckPods(t *testing.T) {
	withProbePolicy(t, ProbePolicy{EnableHostNetworkProbes: true, TargetClasses: map[string]bool{"registry": true}, TLSProbeMode: "handshake-only"})
	if got := imageRegistryHost("nginx"); got != "registry-1.docker.io:443" {
		t.Fatalf("unexpected registry host: %q", got)
	}
	if got := imageRegistryHost("ghcr.io/app/api:v1"); got != "ghcr.io:443" {
		t.Fatalf("unexpected registry host with explicit registry: %q", got)
	}
	if !isImagePull("ErrImagePull") || isImagePull("Running") {
		t.Fatal("unexpected image pull detection")
	}
	if findCondition([]corev1.PodCondition{{Type: corev1.PodReady}}, corev1.PodScheduled) != nil {
		t.Fatal("expected missing condition")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
				Spec: corev1.PodSpec{
					Containers:       []corev1.Container{{Name: "api", Image: "localhost:1/app:latest", ImagePullPolicy: corev1.PullAlways}},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "missing-secret"}},
				},
				Status: corev1.PodStatus{
					Phase:      corev1.PodPending,
					Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable"}},
					ContainerStatuses: []corev1.ContainerStatus{{
						Name:                 "api",
						RestartCount:         6,
						State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ErrImagePull"}},
						LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}},
					}},
				},
			}}})
		case "/api/v1/namespaces/prod/secrets/missing-secret":
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "missing"})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckPods(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckPods returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected several pod issues, got %+v", issues)
	}
}
