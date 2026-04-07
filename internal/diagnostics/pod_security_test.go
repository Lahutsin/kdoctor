package diagnostics

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodSecurityHelpersAndCheckPodSecurity(t *testing.T) {
	privileged := true
	allowPE := true
	runAsRoot := int64(0)
	runAsNonRoot := false
	readOnly := false
	procMount := corev1.UnmaskedProcMount
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:    &runAsRoot,
				RunAsNonRoot: &runAsNonRoot,
				Sysctls:      []corev1.Sysctl{{Name: "kernel.msgmax", Value: "1"}},
			},
			Volumes: []corev1.Volume{{Name: "sock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}}},
			Containers: []corev1.Container{{
				Name:  "api",
				Image: "api:latest",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &privileged,
					AllowPrivilegeEscalation: &allowPE,
					RunAsUser:                &runAsRoot,
					ReadOnlyRootFilesystem:   &readOnly,
					ProcMount:                &procMount,
					Capabilities: &corev1.Capabilities{
						Add:  []corev1.Capability{"SYS_ADMIN"},
						Drop: []corev1.Capability{"NET_RAW"},
					},
					SeccompProfile:  &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
					AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
					SELinuxOptions:  &corev1.SELinuxOptions{Type: "spc_t"},
				},
			}},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox"}}},
		},
	}
	ns := namespaceMeta{
		name:        "prod",
		labels:      map[string]string{"environment": "production", "pod-security.kubernetes.io/enforce": "restricted"},
		annotations: map[string]string{"reason": "approved"},
	}

	if len(evaluatePSANamespaceLabels(map[string]namespaceMeta{"prod": ns, "dev": {name: "dev"}})) == 0 {
		t.Fatal("expected PSA namespace issues")
	}
	if len(evaluatePSAPolicyDrift(map[string]namespaceMeta{"prod": ns, "dev": {name: "dev", labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}})) == 0 {
		t.Fatal("expected PSA drift issue")
	}
	if len(evaluatePodLevelSecurity(pod, ns)) == 0 || len(evaluateContainerSecurity(pod, ns)) == 0 || len(evaluatePSARestrictedViolations(pod, ns)) == 0 {
		t.Fatal("expected pod/container/restricted security issues")
	}
	if len(allSecurityContainers(pod)) != 2 || !isPrivileged(pod.Spec.Containers[0].SecurityContext) || !isAllowPrivilegeEscalation(pod.Spec.Containers[0].SecurityContext) {
		t.Fatal("expected container security helper matches")
	}
	if !runsAsRoot(pod, pod.Spec.Containers[0].SecurityContext) || hasRunAsNonRoot(pod, pod.Spec.Containers[0].SecurityContext) {
		t.Fatal("unexpected run-as-root helpers")
	}
	if len(dangerousCapabilities(pod.Spec.Containers[0].SecurityContext)) == 0 || dropsAllCapabilities(pod.Spec.Containers[0].SecurityContext) {
		t.Fatal("expected capability helper behavior")
	}
	if seccompFinding(pod, pod.Spec.Containers[0].SecurityContext) == "" || appArmorFinding(pod, pod.Spec.Containers[0].SecurityContext) == "" || seLinuxFinding(pod, pod.Spec.Containers[0].SecurityContext) == "" {
		t.Fatal("expected LSM helper findings")
	}
	if !isReadOnlyRootFilesystemFalse(pod.Spec.Containers[0].SecurityContext) || procMountFinding(pod.Spec.Containers[0].SecurityContext) == "" {
		t.Fatal("expected filesystem/procmount helper findings")
	}
	if len(podUnsafeSysctls(pod)) != 1 || isSafeSysctl("kernel.msgmax") || !looksLikeRuntimeSocket("/run/containerd/containerd.sock") {
		t.Fatal("expected sysctl/runtime socket helper behavior")
	}
	if len(restrictedViolations(pod)) < 5 || psaLevel(ns.labels, "enforce") != "restricted" || !isValidPSALevel("baseline") || displayPSALevel("") != "unlabeled" {
		t.Fatal("unexpected restricted/PSA helper behavior")
	}
	if !looksLikeSystemNamespace("istio-system") || justificationForNamespace(ns) == "" || !isSensitiveWorkload(pod, ns) || len(sortedMapKeys(map[string]int{"b": 1, "a": 1})) != 2 {
		t.Fatal("expected namespace classification helpers")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	issues, err := CheckPodSecurity(ctx, cs, "prod")
	if err != nil {
		t.Fatalf("CheckPodSecurity returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected several pod security issues, got %+v", issues)
	}
}
