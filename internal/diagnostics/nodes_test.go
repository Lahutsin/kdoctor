package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNodeHelpersAndCheckNodes(t *testing.T) {
	now := time.Now()
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"tenant": "payments"}},
		Spec:       corev1.NodeSpec{Unschedulable: true, Taints: []corev1.Taint{{Key: "dedicated", Value: "prod", Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse, LastHeartbeatTime: metav1.NewTime(now.Add(-8 * 24 * time.Hour)), Reason: "KubeletDown"}, {Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue}, {Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue}, {Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionTrue}},
			Addresses:  []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "203.0.113.10"}},
		},
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "prod"}, Spec: corev1.PodSpec{NodeName: "node1", Volumes: []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet/pki"}}}}}}
	if nodeReadyCondition(node.Status.Conditions) == nil || nodeNameFromCSRSpec("csr", "system:node:node1", "") != "node1" {
		t.Fatal("unexpected node readiness or CSR helper behavior")
	}
	if len(staleNodeIssues(node, nodeReadyCondition(node.Status.Conditions))) == 0 || len(suspiciousNodeSchedulingMetadataIssues(node)) < 2 || len(sensitiveNodeMountIssues(node, []corev1.Pod{pod})) == 0 {
		t.Fatal("expected stale node and scheduling issues")
	}
	if len(unschedulableReachableNodeIssues(corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node2"}, Spec: corev1.NodeSpec{Unschedulable: true}}, &corev1.NodeCondition{Status: corev1.ConditionTrue}, nodeExposure{externalIP: "203.0.113.11", openPorts: []int{22}})) == 0 {
		t.Fatal("expected unschedulable reachable node issue")
	}
	if groupPodsByNode([]corev1.Pod{pod})["node1"] == nil || nodeAddress(node, corev1.NodeExternalIP) == "" || formatPorts([]int{22, 10250}) == "" {
		t.Fatal("unexpected node grouping and formatting behavior")
	}
	if !hasAnyPort([]int{22, 10250}, 10250) || len(filterPorts([]int{22, 10250}, 22)) != 1 || suspiciousNodeLabels(node.Labels)[0] == "" {
		t.Fatal("unexpected node port and label behavior")
	}
	if len(suspiciousNodeTaints(node.Spec.Taints)) == 0 || !looksPlacementSensitive("tenant", "prod") || trustedNodeMetadataPrefix("kubernetes.io/hostname") == false || !sensitiveNodeHostPath("/var/lib/kubelet/config.yaml") || !isCriticalNodeHostPath("/etc/kubernetes/manifests") {
		t.Fatal("unexpected node sensitivity helpers")
	}

	ctx := context.Background()
	csrCert := generateSelfSignedCertPEM(t, "system:node:node1", time.Now().Add(-time.Hour))
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{node}})
		case "/api/v1/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/api/v1/nodes/node1/proxy/configz":
			writeJSONResponse(t, w, http.StatusOK, map[string]any{"kubeletconfig": map[string]any{"authentication": map[string]any{"anonymous": map[string]any{"enabled": true}, "webhook": map[string]any{"enabled": false}}, "authorization": map[string]any{"mode": "AlwaysAllow"}, "readOnlyPort": 10255}})
		case "/apis/certificates.k8s.io/v1/certificatesigningrequests":
			writeJSONResponse(t, w, http.StatusOK, &certificatesv1.CertificateSigningRequestList{Items: []certificatesv1.CertificateSigningRequest{{ObjectMeta: metav1.ObjectMeta{Name: "csr-node1"}, Spec: certificatesv1.CertificateSigningRequestSpec{SignerName: "kubernetes.io/kubelet-serving", Username: "system:node:node1"}, Status: certificatesv1.CertificateSigningRequestStatus{Certificate: csrCert}}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err := CheckNodes(ctx, cs)
	if err != nil {
		t.Fatalf("CheckNodes returned error: %v", err)
	}
	if len(issues) < 8 {
		t.Fatalf("expected node issues, got %+v", issues)
	}
	if _, err := CheckNodes(ctx, nil); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}