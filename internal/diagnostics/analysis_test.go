package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func newHTTPBackedClientset(t *testing.T, handler http.HandlerFunc) *kubernetes.Clientset {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("create clientset: %v", err)
	}
	return cs
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, status int, object any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if object == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(object); err != nil {
		t.Fatalf("encode json response: %v", err)
	}
}

func withProbePolicy(t *testing.T, policy ProbePolicy) {
	t.Helper()
	previous := CurrentProbePolicy()
	SetProbePolicy(policy)
	t.Cleanup(func() {
		SetProbePolicy(previous)
	})
}

func kubeconfigBytes(t *testing.T, serverURL, authName string, withBasicAuth bool) []byte {
	t.Helper()

	cfg := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"prod": {Server: serverURL},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"prod-admin": {Cluster: "prod", AuthInfo: authName},
		},
		CurrentContext: "prod-admin",
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			authName: {},
		},
	}
	if withBasicAuth {
		cfg.AuthInfos[authName].Username = "admin"
		cfg.AuthInfos[authName].Password = "secret"
	} else {
		cfg.AuthInfos[authName].Token = "static-token"
	}

	raw, err := clientcmd.Write(cfg)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return raw
}

func TestBuildExplanationsAndHelpers(t *testing.T) {
	var issues []Issue
	for index := 0; index < 12; index++ {
		severity := SeverityInfo
		if index == 0 {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:      "Pod",
			Namespace: "team-a",
			Name:      string(rune('a' + index)),
			Severity:  severity,
			Check:     "check-" + string(rune('a'+index)),
			Category:  "workloads",
			Summary:   "issue summary",
		})
	}

	explanations := BuildExplanations(issues)
	if len(explanations) != 10 {
		t.Fatalf("expected explanations capped at 10, got %d", len(explanations))
	}
	if explanations[0].Severity != SeverityCritical {
		t.Fatalf("expected highest severity first, got %+v", explanations[0])
	}
	if explanationTitle("pod-security") != "Pod Security analysis" {
		t.Fatalf("unexpected title: %q", explanationTitle("pod-security"))
	}
	if severityRank(SeverityCritical) != 3 || severityRank(SeverityWarning) != 2 || severityRank(SeverityInfo) != 1 {
		t.Fatal("unexpected severity rank")
	}
	if severityFromEvent("Warning", "BackOff", "failed to start") != SeverityWarning {
		t.Fatal("expected warning severity")
	}
	if severityFromEvent("Normal", "Started", "ok") != SeverityInfo {
		t.Fatal("expected info severity")
	}
	if objectRef("Pod", "prod", "api") != "Pod/prod/api" || objectRef("Node", "", "n1") != "Node/n1" {
		t.Fatal("unexpected object refs")
	}
	if strings.Join(sortedKeys(map[string]struct{}{"b": {}, "a": {}}), ",") != "a,b" {
		t.Fatal("unexpected sorted keys")
	}
	if strings.Join(uniqueStrings([]string{"b", "a", "b", ""}), ",") != "a,b" {
		t.Fatal("unexpected unique strings")
	}
	if normalizeNamespace("") != metav1.NamespaceAll || defaultNamespace("") != "default" {
		t.Fatal("unexpected namespace defaults")
	}
}

func TestAnalysisFilteringRulesAndRemediations(t *testing.T) {
	issues := []Issue{
		{Kind: "Pod", Namespace: "prod", Name: "api", Severity: SeverityWarning, Check: "crashloop", Summary: "api crashloop", Recommendation: "restart pod"},
		{Kind: "Node", Name: "node-a", Severity: SeverityCritical, Check: "nodes-ready", Summary: "node unavailable", Recommendation: "check node"},
		{Kind: "Deployment", Namespace: "prod", Name: "web", Severity: SeverityInfo, Check: "deployment-scaled-zero", Summary: "scaled to zero", Recommendation: "confirm intent"},
		{Kind: "Deployment", Namespace: "prod", Name: "web", Severity: SeverityInfo, Check: "deployment-scaled-zero", Summary: "scaled to zero", Recommendation: "confirm intent"},
		{Kind: "ValidatingWebhookConfiguration", Name: "admission", Severity: SeverityWarning, Check: "webhook-timeout", Summary: "webhook slow", Recommendation: "review webhook"},
	}

	filtered, appliedNoise := ApplyBuiltInNoiseSuppression(issues, true)
	if len(filtered) != 3 || len(appliedNoise) == 0 {
		t.Fatalf("unexpected suppression result: filtered=%d applied=%v", len(filtered), appliedNoise)
	}

	incident := FilterIncidentIssues(issues)
	if len(incident) != 2 {
		t.Fatalf("expected 2 incident issues, got %d", len(incident))
	}

	if len(FilterIssuesByFocus(issues, FocusSpec{Kind: "namespace", Value: "prod"})) != 3 {
		t.Fatal("expected namespace focus to retain prod issues")
	}
	if !focusMatchesIssue(FocusSpec{Kind: "node", Value: "node-a"}, issues[1]) {
		t.Fatal("expected node focus match")
	}
	if !focusMatchesObject(FocusSpec{Kind: "app", Value: "web"}, "prod", "svc", map[string]string{"app": "web"}, "") {
		t.Fatal("expected app focus match")
	}

	steps := BuildRemediations(issues)
	if len(steps) != 4 || !strings.Contains(steps[0].Command, "kubectl") {
		t.Fatalf("unexpected remediations: %+v", steps)
	}

	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	rules := "rules:\n  - name: escalate crashloop\n    match:\n      check: crashloop\n    setSeverity: critical\n    addRecommendation: collect logs\n    addReference: runbook/crashloop\n    appendSummarySuffix: immediately\n  - name: suppress node\n    match:\n      name: node-a\n    suppress: true\n"
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	ruled, applied, err := ApplyRules(issues, rulesPath)
	if err != nil {
		t.Fatalf("ApplyRules returned error: %v", err)
	}
	if len(applied) != 2 || len(ruled) != 4 {
		t.Fatalf("unexpected rule application: applied=%v issues=%d", applied, len(ruled))
	}
	if ruled[0].Severity != SeverityCritical || len(ruled[0].References) == 0 || !strings.Contains(ruled[0].Summary, "immediately") {
		t.Fatalf("expected modified ruled issue, got %+v", ruled[0])
	}

	if countIssuesByCheck(issues, "crashloop") != 1 || countIssuesByCheckPrefix(issues, "deployment-") != 2 {
		t.Fatal("unexpected counters")
	}
	if nodePoolName(map[string]string{"eks.amazonaws.com/nodegroup": "workers"}) != "workers" {
		t.Fatal("unexpected node pool name")
	}
	if !(RuleMatch{SummaryContains: "crash", Namespace: "prod"}).matches(issues[0]) {
		t.Fatal("expected rule match")
	}
}

func TestAnalysisComparisonsAndReadinessHelpers(t *testing.T) {
	baseIssues := []Issue{
		{Kind: "Pod", Namespace: "prod", Name: "api", Severity: SeverityWarning, Check: "crashloop", Summary: "api crashloop"},
		{Kind: "Ingress", Namespace: "prod", Name: "web", Severity: SeverityCritical, Check: "ingress-backend-endpoints", Summary: "backend missing"},
	}
	compareIssues := []Issue{
		{Kind: "Pod", Namespace: "prod", Name: "api", Severity: SeverityWarning, Check: "crashloop", Summary: "api crashloop"},
		{Kind: "Node", Name: "node-a", Severity: SeverityCritical, Check: "nodes-ready", Summary: "node unavailable"},
	}

	comparison := CompareIssueSets("prod", "staging", baseIssues, compareIssues, 80, 65)
	if len(comparison.NewIssues) != 1 || len(comparison.MissingIssues) != 1 {
		t.Fatalf("unexpected comparison result: %+v", comparison)
	}

	readiness := EvaluateReleaseReadiness([]Issue{
		{Check: "resource-quota-hard", Severity: SeverityWarning},
		{Check: "pdb-unavailable", Severity: SeverityWarning},
		{Check: "pdb-overlap", Severity: SeverityWarning},
		{Check: "hpa-metrics", Severity: SeverityWarning},
	})
	if len(readiness) < 3 || readiness[0].Severity != SeverityCritical {
		t.Fatalf("unexpected readiness advisories: %+v", readiness)
	}

	if EvaluatePDBUpgradeImpact([]policyv1.PodDisruptionBudget{{Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0, ExpectedPods: 3}}}) != 1 {
		t.Fatal("expected one blocked pdb")
	}

	ingress := networkingv1.Ingress{Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}}}, {Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}}}}}}}}}}
	backends := IngressBackends(ingress)
	if len(backends) != 1 || backends[0] != "web" {
		t.Fatalf("unexpected ingress backends: %v", backends)
	}

	if len(dedupeEdges([]DependencyEdge{{From: "a", Relation: "uses", To: "b"}, {From: "a", Relation: "uses", To: "b"}, {From: "a", Relation: "uses", To: "c"}})) != 2 {
		t.Fatal("expected deduped edges")
	}

	advisories := []Advisory{{Title: "zeta", Severity: SeverityInfo}, {Title: "alpha", Severity: SeverityCritical}, {Title: "beta", Severity: SeverityWarning}}
	sortAdvisories(advisories)
	if advisories[0].Title != "alpha" {
		t.Fatalf("unexpected advisory order: %+v", advisories)
	}
}

func TestAnalysisViewsAndInsightsWithHTTPClientset(t *testing.T) {
	ctx := context.Background()
	pathType := networkingv1.PathTypePrefix
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
				Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 80}}, Type: corev1.ServiceTypeLoadBalancer},
			}}})
		case "/api/v1/namespaces/prod/endpoints/web":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Endpoints{Subsets: []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.10"}}}}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "prod", Labels: map[string]string{"app": "web"}},
				Spec:       corev1.PodSpec{Volumes: []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "web-config"}}}}}},
			}}})
		case "/apis/networking.k8s.io/v1/namespaces/prod/ingresses":
			writeJSONResponse(t, w, http.StatusOK, &networkingv1.IngressList{Items: []networkingv1.Ingress{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{{
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
								Path:     "/",
								PathType: &pathType,
								Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}},
							}}},
						},
					}},
				},
			}}})
		case "/api/v1/nodes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.NodeList{Items: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{"agentpool": "blue"}}}}})
		case "/apis/apps/v1/namespaces/prod/deployments":
			replicas := int32(1)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", Labels: map[string]string{"app": "web"}},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}},
				},
			}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	views, err := BuildServiceViews(ctx, cs, "prod", "web")
	if err != nil || len(views) != 1 {
		t.Fatalf("unexpected service views: views=%+v err=%v", views, err)
	}
	if len(views[0].Chain) < 3 || len(views[0].Findings) == 0 {
		t.Fatalf("expected populated service view, got %+v", views[0])
	}

	nodeViews, err := BuildNodePoolViews(ctx, cs, []Issue{{Kind: "Node", Name: "node-a", Severity: SeverityCritical, Summary: "node unavailable"}, {Check: "daemonset-availability", Severity: SeverityWarning, Summary: "daemonset unavailable"}})
	if err != nil || len(nodeViews) == 0 {
		t.Fatalf("unexpected node views: views=%+v err=%v", nodeViews, err)
	}

	insights, err := BuildSLOInsights(ctx, cs, "prod", []Issue{{Kind: "Ingress", Namespace: "prod", Severity: SeverityCritical, Check: "ingress-backend-endpoints", Summary: "backend missing"}})
	if err != nil || len(insights) != 1 || insights[0].Severity != SeverityCritical {
		t.Fatalf("unexpected slo insights: insights=%+v err=%v", insights, err)
	}

	edges, err := BuildControllerDependencyEdges(ctx, cs, "prod", FocusSpec{Kind: "app", Value: "web"})
	if err != nil || len(edges) != 1 || edges[0].Relation != "owns" {
		t.Fatalf("unexpected controller edges: edges=%+v err=%v", edges, err)
	}

	deps, err := BuildDependencies(ctx, cs, "prod", FocusSpec{Kind: "app", Value: "web"})
	if err != nil || len(deps) < 2 {
		t.Fatalf("unexpected dependencies: deps=%+v err=%v", deps, err)
	}

	paths, err := BuildNetworkPaths(ctx, cs, "prod", FocusSpec{Kind: "app", Value: "web"})
	if err != nil || len(paths) == 0 {
		t.Fatalf("unexpected network paths: paths=%+v err=%v", paths, err)
	}

	storagePaths, err := BuildStoragePaths(ctx, cs, "prod", FocusSpec{})
	if err == nil {
		_ = storagePaths
	}
	if err == nil {
		t.Fatal("expected storage paths call to fail without pvc endpoint")
	}
}

func TestAnalysisOperationalSignalsWithHTTPClientset(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/events":
			writeJSONResponse(t, w, http.StatusOK, &corev1.EventList{Items: []corev1.Event{{
				ObjectMeta:     metav1.ObjectMeta{Name: "pod-warning", Namespace: "prod", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
				Type:           "Warning",
				Reason:         "BackOff",
				Message:        "failed to pull image",
				InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "prod", Name: "api"},
				LastTimestamp:  metav1.NewTime(now.Add(-30 * time.Second)),
			}}})
		case "/apis/apps/v1/namespaces/prod/deployments":
			replicas := int32(1)
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DeploymentList{Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}}}})
		case "/api/v1/namespaces/prod/pods":
			privileged := true
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}},
					Volumes:    []corev1.Volume{{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib"}}}},
				},
			}}})
		case "/api/v1/namespaces/prod/services":
			writeJSONResponse(t, w, http.StatusOK, &corev1.ServiceList{Items: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "prod"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer}}}})
		case "/api/v1/namespaces/prod/endpoints/lb":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Endpoints{})
		case "/api/v1/namespaces/prod/persistentvolumeclaims":
			storageClass := "fast"
			writeJSONResponse(t, w, http.StatusOK, &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "prod"},
				Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &storageClass, VolumeName: "pv-data"},
			}, {
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "prod"},
			}}})
		case "/apis/storage.k8s.io/v1/volumeattachments":
			pvName := "pv-data"
			writeJSONResponse(t, w, http.StatusOK, &storagev1.VolumeAttachmentList{Items: []storagev1.VolumeAttachment{{
				ObjectMeta: metav1.ObjectMeta{Name: "attach-pv-data"},
				Spec: storagev1.VolumeAttachmentSpec{
					Attacher: "csi.test",
					NodeName: "node-a",
					Source:   storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvName},
				},
			}}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	timeline, err := BuildTimeline(ctx, cs, "prod", 5)
	if err != nil || len(timeline) != 1 || timeline[0].Severity != SeverityWarning {
		t.Fatalf("unexpected timeline result: timeline=%+v err=%v", timeline, err)
	}

	issues := []Issue{
		{Check: "pdb-unavailable", Severity: SeverityWarning},
		{Check: "node-cordoned", Severity: SeverityWarning},
		{Check: "webhook-timeout", Severity: SeverityWarning},
		{Category: "security", Severity: SeverityWarning},
		{Check: "deployment-scaled-zero", Severity: SeverityInfo},
		{Check: "pv-orphaned", Severity: SeverityInfo},
	}

	upgrade, err := EvaluateUpgradeReadiness(ctx, cs, "prod", issues)
	if err != nil || len(upgrade) < 3 {
		t.Fatalf("unexpected upgrade advisories: advisories=%+v err=%v", upgrade, err)
	}

	security, err := EvaluateSecurityPosture(ctx, cs, "prod", issues)
	if err != nil || len(security) < 3 {
		t.Fatalf("unexpected security advisories: advisories=%+v err=%v", security, err)
	}

	cost, err := EvaluateCostWaste(ctx, cs, "prod", issues)
	if err != nil || len(cost) < 2 {
		t.Fatalf("unexpected cost advisories: advisories=%+v err=%v", cost, err)
	}

	paths, err := BuildStoragePaths(ctx, cs, "prod", FocusSpec{})
	if err != nil || len(paths) != 2 {
		t.Fatalf("unexpected storage paths: paths=%+v err=%v", paths, err)
	}
	if len(paths[0].Steps) < 4 && len(paths[1].Findings) == 0 {
		t.Fatalf("expected bound and pending pvc paths, got %+v", paths)
	}
}
