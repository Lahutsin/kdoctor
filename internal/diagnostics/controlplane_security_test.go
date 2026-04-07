package diagnostics

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControlPlaneSecurityHelpers(t *testing.T) {
	apiserverPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-prod"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Command: []string{"kube-apiserver"}, Args: []string{"--authorization-mode=AlwaysAllow", "--insecure-port=8080", "--disable-admission-plugins=PodSecurity", "--audit-log-maxage=3"}}}}}
	flags := collectContainerFlags(apiserverPod)
	if firstFlagValue(flags, "authorization-mode") != "AlwaysAllow" || firstFlagInt(flags, "audit-log-maxage") != 3 {
		t.Fatalf("unexpected parsed flags: %+v", flags)
	}
	if firstFlagDuration(map[string][]string{"cluster-signing-duration": {"365d"}}, "cluster-signing-duration") <= 0 {
		t.Fatal("expected day duration parsing")
	}
	if isFlagFalse(map[string][]string{"anonymous-auth": {"false"}}, "anonymous-auth") == false || !insecurePortEnabled(map[string][]string{"port": {"10251"}}, "port") {
		t.Fatal("unexpected flag helpers")
	}
	if !containsFold([]string{"RBAC", "Node"}, "rbac") {
		t.Fatal("expected case-insensitive contains")
	}
	if len(inspectAPIServerSecurity(apiserverPod)) == 0 {
		t.Fatal("expected apiserver security issues")
	}
	etcdPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "etcd-prod"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--listen-client-urls=http://127.0.0.1:2379"}}}}}
	if len(inspectEtcdSecurity(etcdPod)) == 0 {
		t.Fatal("expected etcd security issues")
	}
	schedulerPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-scheduler"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--port=10251"}}}}}
	if len(inspectSchedulerSecurity(schedulerPod)) == 0 {
		t.Fatal("expected scheduler security issues")
	}
	controllerPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-controller-manager"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--port=10252", "--cluster-signing-duration=500d"}}}}}
	if len(inspectControllerManagerSecurity(controllerPod)) == 0 {
		t.Fatal("expected controller-manager security issues")
	}
	issue := controlPlaneSecurityIssue("APIServer", "api", "check", SeverityWarning, "summary", "rec")
	if issue.Namespace != metav1.NamespaceSystem || issue.Category != "security" {
		t.Fatalf("unexpected issue helper: %+v", issue)
	}
	leafPEM, caPEM := generateCAAndLeafPEM(t, "ca", "leaf", time.Now().Add(24*time.Hour))
	if problems := verifyCertificateChain("kube-system", "api", leafPEM, caPEM); len(problems) != 0 {
		t.Fatalf("expected valid certificate chain, got %+v", problems)
	}
	if problems := verifyCertificateChain("kube-system", "api", leafPEM, generateSelfSignedCertPEM(t, "other-ca", time.Now().Add(365*24*time.Hour))); len(problems) == 0 {
		t.Fatal("expected invalid certificate chain issue")
	}
	csr := &certificatesv1.CertificateSigningRequest{Status: certificatesv1.CertificateSigningRequestStatus{Conditions: []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue, LastUpdateTime: metav1.NewTime(time.Now())}}}}
	if !csrApproved(csr) || csrApprovalTime(csr).IsZero() {
		t.Fatal("expected approved csr helpers")
	}
}

func TestCheckControlPlaneSecurity(t *testing.T) {
	ctx := context.Background()
	leafPEM, caPEM := generateCAAndLeafPEM(t, "cluster-ca", "apiserver", time.Now().Add(2*24*time.Hour))
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-node1", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--authorization-mode=AlwaysAllow", "--insecure-port=8080", "--disable-admission-plugins=PodSecurity"}}}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "etcd-node1", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--listen-client-urls=http://127.0.0.1:2379"}}}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-scheduler-node1", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-scheduler"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--port=10251"}}}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-controller-manager-node1", Namespace: metav1.NamespaceSystem, Labels: map[string]string{"component": "kube-controller-manager"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Args: []string{"--port=10252", "--cluster-signing-duration=500d"}}}}},
			}})
		case "/api/v1/namespaces/kube-system/secrets":
			writeJSONResponse(t, w, http.StatusOK, &corev1.SecretList{Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-tls", Namespace: metav1.NamespaceSystem}, Data: map[string][]byte{"tls.crt": leafPEM, "ca.crt": caPEM}}}})
		case "/apis/certificates.k8s.io/v1/certificatesigningrequests":
			writeJSONResponse(t, w, http.StatusOK, &certificatesv1.CertificateSigningRequestList{Items: []certificatesv1.CertificateSigningRequest{{ObjectMeta: metav1.ObjectMeta{Name: "pending-csr", CreationTimestamp: metav1.NewTime(time.Now().Add(-48 * time.Hour))}, Spec: certificatesv1.CertificateSigningRequestSpec{SignerName: certificatesv1.KubeletServingSignerName}}}})
		case "/metrics":
			_, _ = w.Write([]byte("apiserver_requested_deprecated_apis{group=\"extensions\",version=\"v1beta1\",resource=\"ingresses\"} 1\n"))
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	components, err := discoverControlPlaneComponents(ctx, cs)
	if err != nil || firstComponentPod(components["kube-apiserver"]) == nil {
		t.Fatalf("unexpected component discovery: components=%+v err=%v", components, err)
	}
	issues, err := CheckControlPlaneSecurity(ctx, cs)
	if err != nil {
		t.Fatalf("CheckControlPlaneSecurity returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected many control-plane security issues, got %+v", issues)
	}
	if deprecated := inspectDeprecatedAPIs(ctx, cs); len(deprecated) == 0 || !strings.Contains(deprecated[0].Summary, "deprecated API usage") {
		t.Fatalf("expected deprecated api issues, got %+v", deprecated)
	}
	if pending := inspectCertificateRotation(ctx, cs); len(pending) == 0 {
		t.Fatal("expected certificate rotation issues")
	}
	if _, err := CheckControlPlaneSecurity(ctx, nil); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
