package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type Explanation struct {
	Title      string   `json:"title"`
	Severity   Severity `json:"severity"`
	Summary    string   `json:"summary"`
	IssueCount int      `json:"issueCount"`
	Checks     []string `json:"checks,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

type TimelineEntry struct {
	Time      time.Time `json:"time"`
	Severity  Severity  `json:"severity"`
	Kind      string    `json:"kind"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
}

type DependencyEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

type PathResult struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Steps    []string `json:"steps"`
	Findings []string `json:"findings,omitempty"`
}

type Advisory struct {
	Title          string   `json:"title"`
	Severity       Severity `json:"severity"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation"`
}

type ServiceView struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Chain     []string `json:"chain"`
	Findings  []string `json:"findings,omitempty"`
}

type NodePoolView struct {
	Name       string   `json:"name"`
	NodeCount  int      `json:"nodeCount"`
	Nodes      []string `json:"nodes,omitempty"`
	Findings   []string `json:"findings,omitempty"`
	Severities []string `json:"severities,omitempty"`
}

type SLOInsight struct {
	Service     string   `json:"service"`
	Namespace   string   `json:"namespace"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	BlastRadius int      `json:"blastRadius"`
	Risk        string   `json:"risk"`
}

type ClusterComparison struct {
	BaseContext    string         `json:"baseContext"`
	CompareContext string         `json:"compareContext"`
	BaseScore      int            `json:"baseScore"`
	CompareScore   int            `json:"compareScore"`
	NewIssues      []Issue        `json:"newIssues,omitempty"`
	MissingIssues  []Issue        `json:"missingIssues,omitempty"`
	CategoryDelta  map[string]int `json:"categoryDelta,omitempty"`
	SeverityDelta  map[string]int `json:"severityDelta,omitempty"`
}

type RemediationStep struct {
	Title   string `json:"title"`
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

type FocusSpec struct {
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value,omitempty"`
}

type RuleFile struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	Name                string    `json:"name" yaml:"name"`
	Match               RuleMatch `json:"match" yaml:"match"`
	SetSeverity         Severity  `json:"setSeverity,omitempty" yaml:"setSeverity,omitempty"`
	AddRecommendation   string    `json:"addRecommendation,omitempty" yaml:"addRecommendation,omitempty"`
	AddReference        string    `json:"addReference,omitempty" yaml:"addReference,omitempty"`
	Suppress            bool      `json:"suppress,omitempty" yaml:"suppress,omitempty"`
	AppendSummarySuffix string    `json:"appendSummarySuffix,omitempty" yaml:"appendSummarySuffix,omitempty"`
}

type RuleMatch struct {
	Category        string   `json:"category,omitempty" yaml:"category,omitempty"`
	Check           string   `json:"check,omitempty" yaml:"check,omitempty"`
	Kind            string   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Namespace       string   `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name            string   `json:"name,omitempty" yaml:"name,omitempty"`
	Severity        Severity `json:"severity,omitempty" yaml:"severity,omitempty"`
	SummaryContains string   `json:"summaryContains,omitempty" yaml:"summaryContains,omitempty"`
}

func BuildExplanations(issues []Issue) []Explanation {
	if len(issues) == 0 {
		return nil
	}
	type bucket struct {
		severity   Severity
		count      int
		checks     map[string]struct{}
		categories map[string]struct{}
		namespaces map[string]struct{}
	}
	buckets := map[string]*bucket{}
	for _, issue := range issues {
		key := issue.Check
		if key == "" {
			key = issue.EffectiveCategory()
		}
		b := buckets[key]
		if b == nil {
			b = &bucket{severity: issue.Severity, checks: map[string]struct{}{}, categories: map[string]struct{}{}, namespaces: map[string]struct{}{}}
			buckets[key] = b
		}
		b.count++
		if severityRank(issue.Severity) > severityRank(b.severity) {
			b.severity = issue.Severity
		}
		if issue.Check != "" {
			b.checks[issue.Check] = struct{}{}
		}
		b.categories[issue.EffectiveCategory()] = struct{}{}
		if issue.Namespace != "" {
			b.namespaces[issue.Namespace] = struct{}{}
		}
	}

	explanations := make([]Explanation, 0, len(buckets))
	for key, bucket := range buckets {
		explanations = append(explanations, Explanation{
			Title:      explanationTitle(key),
			Severity:   bucket.severity,
			Summary:    fmt.Sprintf("%d related findings grouped under %s", bucket.count, key),
			IssueCount: bucket.count,
			Checks:     sortedKeys(bucket.checks),
			Categories: sortedKeys(bucket.categories),
			Namespaces: sortedKeys(bucket.namespaces),
		})
	}

	sort.SliceStable(explanations, func(i, j int) bool {
		if severityRank(explanations[i].Severity) != severityRank(explanations[j].Severity) {
			return severityRank(explanations[i].Severity) > severityRank(explanations[j].Severity)
		}
		return explanations[i].IssueCount > explanations[j].IssueCount
	})
	if len(explanations) > 10 {
		return explanations[:10]
	}
	return explanations
}

func BuildTimeline(ctx context.Context, cs *kubernetes.Clientset, namespace string, limit int) ([]TimelineEntry, error) {
	if cs == nil {
		return nil, nil
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}
	events, err := cs.CoreV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	entries := make([]TimelineEntry, 0, len(events.Items))
	for _, ev := range events.Items {
		when := ev.EventTime.Time
		if when.IsZero() {
			when = ev.LastTimestamp.Time
		}
		if when.IsZero() {
			when = ev.CreationTimestamp.Time
		}
		if when.IsZero() {
			continue
		}
		entries = append(entries, TimelineEntry{
			Time:      when,
			Severity:  severityFromEvent(ev.Type, ev.Reason, ev.Message),
			Kind:      ev.InvolvedObject.Kind,
			Namespace: ev.InvolvedObject.Namespace,
			Name:      ev.InvolvedObject.Name,
			Reason:    ev.Reason,
			Message:   ev.Message,
		})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Time.After(entries[j].Time) })
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func BuildDependencies(ctx context.Context, cs *kubernetes.Clientset, namespace string, focus FocusSpec) ([]DependencyEdge, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	edges := make([]DependencyEdge, 0)

	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ing := range ingresses.Items {
			if !focusMatchesObject(focus, ing.Namespace, ing.Name, ing.Labels, "") {
				continue
			}
			for _, rule := range ing.Spec.Rules {
				if rule.HTTP == nil {
					continue
				}
				for _, path := range rule.HTTP.Paths {
					if path.Backend.Service == nil {
						continue
					}
					edges = append(edges, DependencyEdge{From: objectRef("Ingress", ing.Namespace, ing.Name), To: objectRef("Service", ing.Namespace, path.Backend.Service.Name), Relation: "routes-to"})
				}
			}
		}
	}

	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, svc := range services.Items {
			if !focusMatchesObject(focus, svc.Namespace, svc.Name, svc.Labels, "") {
				continue
			}
			selector := labels.SelectorFromSet(svc.Spec.Selector)
			if len(svc.Spec.Selector) == 0 {
				continue
			}
			pods, podsErr := cs.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
			if podsErr != nil {
				continue
			}
			for _, pod := range pods.Items {
				edges = append(edges, DependencyEdge{From: objectRef("Service", svc.Namespace, svc.Name), To: objectRef("Pod", pod.Namespace, pod.Name), Relation: "selects"})
			}
		}
	}

	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, pod := range pods.Items {
			if !focusMatchesObject(focus, pod.Namespace, pod.Name, pod.Labels, pod.Spec.NodeName) {
				continue
			}
			for _, volume := range pod.Spec.Volumes {
				switch {
				case volume.PersistentVolumeClaim != nil:
					edges = append(edges, DependencyEdge{From: objectRef("Pod", pod.Namespace, pod.Name), To: objectRef("PVC", pod.Namespace, volume.PersistentVolumeClaim.ClaimName), Relation: "mounts"})
				case volume.Secret != nil:
					edges = append(edges, DependencyEdge{From: objectRef("Pod", pod.Namespace, pod.Name), To: objectRef("Secret", pod.Namespace, volume.Secret.SecretName), Relation: "depends-on"})
				case volume.ConfigMap != nil:
					edges = append(edges, DependencyEdge{From: objectRef("Pod", pod.Namespace, pod.Name), To: objectRef("ConfigMap", pod.Namespace, volume.ConfigMap.Name), Relation: "depends-on"})
				}
			}
		}
	}

	return dedupeEdges(edges), nil
}

func BuildNetworkPaths(ctx context.Context, cs *kubernetes.Clientset, namespace string, focus FocusSpec) ([]PathResult, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	paths := make([]PathResult, 0)
	ingresses, err := cs.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ing := range ingresses.Items {
			if !focusMatchesObject(focus, ing.Namespace, ing.Name, ing.Labels, "") {
				continue
			}
			path := PathResult{Kind: "Ingress", Name: objectRef("Ingress", ing.Namespace, ing.Name)}
			path.Steps = append(path.Steps, objectRef("Ingress", ing.Namespace, ing.Name))
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					path.Steps = append(path.Steps, fmt.Sprintf("Host:%s", rule.Host))
				}
				if rule.HTTP == nil {
					continue
				}
				for _, httpPath := range rule.HTTP.Paths {
					if httpPath.Backend.Service == nil {
						continue
					}
					svcName := httpPath.Backend.Service.Name
					path.Steps = append(path.Steps, objectRef("Service", ing.Namespace, svcName))
					eps, epsErr := cs.CoreV1().Endpoints(ing.Namespace).Get(ctx, svcName, metav1.GetOptions{})
					if epsErr == nil && hasReadyAddress(eps) {
						path.Findings = append(path.Findings, fmt.Sprintf("service %s has ready endpoints", svcName))
					} else {
						path.Findings = append(path.Findings, fmt.Sprintf("service %s lacks ready endpoints", svcName))
					}
				}
			}
			paths = append(paths, path)
		}
	}

	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err == nil && len(paths) < 10 {
		for _, svc := range services.Items {
			if !focusMatchesObject(focus, svc.Namespace, svc.Name, svc.Labels, "") {
				continue
			}
			selector := labels.SelectorFromSet(svc.Spec.Selector)
			path := PathResult{Kind: "Service", Name: objectRef("Service", svc.Namespace, svc.Name)}
			path.Steps = append(path.Steps, objectRef("DNS", "", fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace)), objectRef("Service", svc.Namespace, svc.Name))
			if len(svc.Spec.Selector) == 0 {
				path.Findings = append(path.Findings, "service has no selectors; backing endpoints must be managed manually")
			} else {
				pods, podsErr := cs.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 5})
				if podsErr == nil {
					for _, pod := range pods.Items {
						path.Steps = append(path.Steps, objectRef("Pod", pod.Namespace, pod.Name))
					}
				}
			}
			paths = append(paths, path)
			if len(paths) >= 10 {
				break
			}
		}
	}
	return paths, nil
}

func BuildStoragePaths(ctx context.Context, cs *kubernetes.Clientset, namespace string, focus FocusSpec) ([]PathResult, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	pvcs, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	paths := make([]PathResult, 0)
	for _, pvc := range pvcs.Items {
		if !focusMatchesObject(focus, pvc.Namespace, pvc.Name, pvc.Labels, "") {
			continue
		}
		path := PathResult{Kind: "PVC", Name: objectRef("PVC", pvc.Namespace, pvc.Name)}
		path.Steps = append(path.Steps, objectRef("PVC", pvc.Namespace, pvc.Name))
		if pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "" {
			path.Steps = append(path.Steps, objectRef("StorageClass", "", *pvc.Spec.StorageClassName))
		}
		if pvc.Spec.VolumeName != "" {
			path.Steps = append(path.Steps, objectRef("PV", "", pvc.Spec.VolumeName))
			attachments, attachErr := cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
			if attachErr == nil {
				for _, attachment := range attachments.Items {
					if attachment.Spec.Source.PersistentVolumeName != nil && *attachment.Spec.Source.PersistentVolumeName == pvc.Spec.VolumeName {
						path.Steps = append(path.Steps, objectRef("VolumeAttachment", "", attachment.Name))
						if attachment.Spec.NodeName != "" {
							path.Steps = append(path.Steps, objectRef("Node", "", attachment.Spec.NodeName))
						}
					}
				}
			}
		} else {
			path.Findings = append(path.Findings, "PVC is not yet bound to a PV")
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func EvaluateUpgradeReadiness(ctx context.Context, cs *kubernetes.Clientset, namespace string, issues []Issue) ([]Advisory, error) {
	advisories := make([]Advisory, 0)
	criticalPDB := countIssuesByCheckPrefix(issues, "pdb-")
	if criticalPDB > 0 {
		advisories = append(advisories, Advisory{Title: "Pod Disruption Budgets", Severity: SeverityWarning, Summary: fmt.Sprintf("%d PDB findings may block node drains or upgrades", criticalPDB), Recommendation: "Review disruptionsAllowed, selector overlap, and expected pod counts before upgrading nodes."})
	}
	if countIssuesByCheck(issues, "node-cordoned") > 0 || countIssuesByCheck(issues, "nodes-ready") > 0 {
		advisories = append(advisories, Advisory{Title: "Node Availability", Severity: SeverityWarning, Summary: "Some nodes are cordoned or not ready", Recommendation: "Stabilize node readiness and clear maintenance cordons before starting an upgrade."})
	}
	if countIssuesByCheckPrefix(issues, "webhook-") > 0 {
		advisories = append(advisories, Advisory{Title: "Admission Webhooks", Severity: SeverityWarning, Summary: "Admission webhooks show availability or latency findings", Recommendation: "Reduce webhook fragility before cluster upgrades to avoid blocked creates/updates."})
	}
	if cs != nil {
		ns := normalizeNamespace(namespace)
		deployments, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			singleReplica := 0
			for _, deploy := range deployments.Items {
				desired := int32(1)
				if deploy.Spec.Replicas != nil {
					desired = *deploy.Spec.Replicas
				}
				if desired == 1 {
					singleReplica++
				}
			}
			if singleReplica > 0 {
				advisories = append(advisories, Advisory{Title: "Single Replica Workloads", Severity: SeverityInfo, Summary: fmt.Sprintf("%d deployments run with a single replica", singleReplica), Recommendation: "Scale critical deployments to at least two replicas before disruptive maintenance."})
			}
		}
	}
	sortAdvisories(advisories)
	return advisories, nil
}

func EvaluateSecurityPosture(ctx context.Context, cs *kubernetes.Clientset, namespace string, issues []Issue) ([]Advisory, error) {
	advisories := make([]Advisory, 0)
	securityFindings := 0
	for _, issue := range issues {
		if issue.EffectiveCategory() == "security" {
			securityFindings++
		}
	}
	if securityFindings > 0 {
		advisories = append(advisories, Advisory{Title: "Existing Security Findings", Severity: SeverityWarning, Summary: fmt.Sprintf("%d security-related findings were detected", securityFindings), Recommendation: "Address expiring certificates, webhook fragility, and other admission/TLS findings first."})
	}
	if cs != nil {
		ns := normalizeNamespace(namespace)
		pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			defaultSA := 0
			privileged := 0
			hostPath := 0
			for _, pod := range pods.Items {
				if pod.Spec.ServiceAccountName == "" || pod.Spec.ServiceAccountName == "default" {
					defaultSA++
				}
				for _, container := range pod.Spec.Containers {
					if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
						privileged++
					}
				}
				for _, volume := range pod.Spec.Volumes {
					if volume.HostPath != nil {
						hostPath++
					}
				}
			}
			if defaultSA > 0 {
				advisories = append(advisories, Advisory{Title: "Default Service Accounts", Severity: SeverityInfo, Summary: fmt.Sprintf("%d pods use the default service account", defaultSA), Recommendation: "Use dedicated service accounts for production workloads with least-privilege RBAC."})
			}
			if privileged > 0 {
				advisories = append(advisories, Advisory{Title: "Privileged Containers", Severity: SeverityWarning, Summary: fmt.Sprintf("%d containers run privileged", privileged), Recommendation: "Review whether privileged mode is necessary and constrain it with node isolation and policy controls."})
			}
			if hostPath > 0 {
				advisories = append(advisories, Advisory{Title: "HostPath Volumes", Severity: SeverityInfo, Summary: fmt.Sprintf("%d pod volumes use hostPath", hostPath), Recommendation: "Limit hostPath usage to trusted workloads and validate path whitelisting controls."})
			}
		}
	}
	sortAdvisories(advisories)
	return advisories, nil
}

func EvaluateCostWaste(ctx context.Context, cs *kubernetes.Clientset, namespace string, issues []Issue) ([]Advisory, error) {
	advisories := make([]Advisory, 0)
	if countIssuesByCheck(issues, "deployment-scaled-zero") > 0 || countIssuesByCheck(issues, "replicaset-scaled-zero") > 0 {
		advisories = append(advisories, Advisory{Title: "Scaled Down Workloads", Severity: SeverityInfo, Summary: "Some workloads are intentionally scaled to zero", Recommendation: "Remove abandoned workloads and related resources if they are no longer needed."})
	}
	if countIssuesByCheck(issues, "pv-orphaned") > 0 {
		advisories = append(advisories, Advisory{Title: "Orphaned Volumes", Severity: SeverityInfo, Summary: "Unbound persistent volumes were detected", Recommendation: "Delete stale PVs or reclaim them to reduce unused storage costs."})
	}
	if cs != nil {
		ns := normalizeNamespace(namespace)
		services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			idleLB := 0
			for _, svc := range services.Items {
				if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
					continue
				}
				eps, epsErr := cs.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
				if epsErr == nil && !hasReadyAddress(eps) {
					idleLB++
				}
			}
			if idleLB > 0 {
				advisories = append(advisories, Advisory{Title: "Idle LoadBalancers", Severity: SeverityWarning, Summary: fmt.Sprintf("%d LoadBalancer services have no ready endpoints", idleLB), Recommendation: "Remove idle LoadBalancer services or restore healthy backends to avoid paying for unused front doors."})
			}
		}
	}
	sortAdvisories(advisories)
	return advisories, nil
}

func BuildRemediations(issues []Issue) []RemediationStep {
	steps := make([]RemediationStep, 0, len(issues))
	seen := map[string]struct{}{}
	for _, issue := range issues {
		var command string
		switch issue.Kind {
		case "Pod":
			command = fmt.Sprintf("kubectl describe pod %s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "Deployment":
			command = fmt.Sprintf("kubectl rollout status deploy/%s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "Node":
			command = fmt.Sprintf("kubectl describe node %s", issue.Name)
		case "Ingress":
			command = fmt.Sprintf("kubectl describe ingress %s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "PVC":
			command = fmt.Sprintf("kubectl describe pvc %s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "HPA":
			command = fmt.Sprintf("kubectl describe hpa %s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "PDB":
			command = fmt.Sprintf("kubectl describe pdb %s -n %s", issue.Name, defaultNamespace(issue.Namespace))
		case "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration":
			command = fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(issue.Kind), issue.Name)
		default:
			if issue.Namespace != "" && issue.Name != "" {
				command = fmt.Sprintf("kubectl describe %s %s -n %s", strings.ToLower(issue.Kind), issue.Name, issue.Namespace)
			}
		}
		if command == "" {
			continue
		}
		if _, ok := seen[command]; ok {
			continue
		}
		seen[command] = struct{}{}
		steps = append(steps, RemediationStep{Title: issue.Summary, Command: command, Reason: issue.Recommendation})
	}
	return steps
}

func ApplyBuiltInNoiseSuppression(issues []Issue, enabled bool) ([]Issue, []string) {
	if !enabled {
		return issues, nil
	}
	suppressedChecks := map[string]string{
		"deployment-scaled-zero": "scaled-zero workloads are commonly intentional",
		"replicaset-scaled-zero": "scaled-zero workloads are commonly intentional",
		"cronjob-suspended":      "suspended cronjobs are often intentional",
		"webhook-failure-policy": "failurePolicy visibility is informational by default",
		"webhook-timeout":        "default timeout informational signal suppressed",
		"pv-orphaned":            "orphaned PV info suppressed outside cost-focused views",
	}
	filtered := make([]Issue, 0, len(issues))
	applied := make([]string, 0)
	for _, issue := range issues {
		reason, ok := suppressedChecks[issue.Check]
		if ok && issue.Severity == SeverityInfo {
			applied = append(applied, fmt.Sprintf("%s: %s", issue.Check, reason))
			continue
		}
		filtered = append(filtered, issue)
	}
	return filtered, uniqueStrings(applied)
}

func FilterIncidentIssues(issues []Issue) []Issue {
	criticalChecks := map[string]bool{
		"pods": true,
	}
	_ = criticalChecks
	filtered := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		if issue.Severity == SeverityInfo {
			continue
		}
		switch issue.Check {
		case "image-pull", "crashloop", "pod-scheduling", "nodes-ready", "node-memory-pressure", "node-disk-pressure", "node-network-unavailable", "apiserver", "dns", "dns-endpoints", "cni", "csi", "controlplane-pods", "etcd-livez", "ingress-loadbalancer", "ingress-backend-endpoints", "webhook-endpoints", "webhook-latency", "pvc-binding", "volume-attachment", "gpu-device-plugin-missing", "gpu-daemonset-unavailable", "gpu-runtime-mismatch", "gpu-scheduling-event", "gpu-profile-unavailable", "gpu-oversubscription-profile-mismatch":
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

func BuildServiceViews(ctx context.Context, cs *kubernetes.Clientset, namespace, serviceName string) ([]ServiceView, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	views := make([]ServiceView, 0)
	for _, svc := range services.Items {
		if serviceName != "" && svc.Name != serviceName {
			continue
		}
		view := ServiceView{Name: svc.Name, Namespace: svc.Namespace}
		view.Chain = append(view.Chain, objectRef("Service", svc.Namespace, svc.Name))
		ingresses, ingErr := cs.NetworkingV1().Ingresses(svc.Namespace).List(ctx, metav1.ListOptions{})
		if ingErr == nil {
			for _, ing := range ingresses.Items {
				for _, backend := range IngressBackends(ing) {
					if backend == svc.Name {
						view.Chain = append([]string{objectRef("Ingress", ing.Namespace, ing.Name)}, view.Chain...)
					}
				}
			}
		}
		eps, epsErr := cs.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if epsErr == nil {
			if hasReadyAddress(eps) {
				view.Findings = append(view.Findings, "service has ready endpoints")
			} else {
				view.Findings = append(view.Findings, "service has no ready endpoints")
			}
		}
		if len(svc.Spec.Selector) > 0 {
			selector := labels.SelectorFromSet(svc.Spec.Selector)
			pods, podsErr := cs.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
			if podsErr == nil {
				for _, pod := range pods.Items {
					view.Chain = append(view.Chain, objectRef("Pod", pod.Namespace, pod.Name))
					for _, volume := range pod.Spec.Volumes {
						switch {
						case volume.PersistentVolumeClaim != nil:
							view.Chain = append(view.Chain, objectRef("PVC", pod.Namespace, volume.PersistentVolumeClaim.ClaimName))
						case volume.Secret != nil:
							view.Chain = append(view.Chain, objectRef("Secret", pod.Namespace, volume.Secret.SecretName))
						case volume.ConfigMap != nil:
							view.Chain = append(view.Chain, objectRef("ConfigMap", pod.Namespace, volume.ConfigMap.Name))
						}
					}
				}
			}
		}
		view.Chain = uniqueStrings(view.Chain)
		views = append(views, view)
	}
	return views, nil
}

func BuildNodePoolViews(ctx context.Context, cs *kubernetes.Clientset, issues []Issue) ([]NodePoolView, error) {
	if cs == nil {
		return nil, nil
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	type bucket struct {
		nodes      []string
		findings   []string
		severities []string
	}
	groups := map[string]*bucket{}
	for _, node := range nodes.Items {
		pool := nodePoolName(node.Labels)
		b := groups[pool]
		if b == nil {
			b = &bucket{}
			groups[pool] = b
		}
		b.nodes = append(b.nodes, node.Name)
	}
	for _, issue := range issues {
		if issue.Kind != "Node" && issue.Check != "daemonset-availability" {
			continue
		}
		pool := "ungrouped"
		if issue.Kind == "Node" {
			for _, node := range nodes.Items {
				if node.Name == issue.Name {
					pool = nodePoolName(node.Labels)
					break
				}
			}
		}
		b := groups[pool]
		if b == nil {
			b = &bucket{}
			groups[pool] = b
		}
		b.findings = append(b.findings, issue.Summary)
		b.severities = append(b.severities, string(issue.Severity))
	}
	views := make([]NodePoolView, 0, len(groups))
	for name, bucket := range groups {
		views = append(views, NodePoolView{
			Name:       name,
			NodeCount:  len(bucket.nodes),
			Nodes:      uniqueStrings(bucket.nodes),
			Findings:   uniqueStrings(bucket.findings),
			Severities: uniqueStrings(bucket.severities),
		})
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	return views, nil
}

func EvaluateReleaseReadiness(issues []Issue) []Advisory {
	advisories := make([]Advisory, 0)
	checks := []struct {
		title   string
		prefix  string
		summary string
		rec     string
	}{
		{"Quota Pressure", "resource-quota", "namespace quota issues may block rollout", "Increase quota headroom or reduce resource usage before deployment."},
		{"PDB Coverage", "pdb-", "PDB findings may block safe rollout or drain handling", "Validate disruption budgets for workloads touched by the release."},
		{"Image Pull Secrets", "image-pull-secret", "image pull secret issues may block new pods", "Verify registry credentials before deploying new images."},
		{"Admission Webhooks", "webhook-", "webhook findings may block creates or updates", "Stabilize admission webhooks prior to deployment."},
		{"Ingress TLS", "ingress-tls-secret", "ingress TLS issues may block external traffic after release", "Fix TLS secret and certificate issues before exposing new routes."},
		{"Autoscaling", "hpa-", "HPA findings may cause incorrect scale behavior during release", "Check metrics and scaling constraints before rollout."},
		{"Storage", "pvc-", "storage findings may block workload startup", "Validate PVC binding and CSI health before deployment."},
	}
	for _, item := range checks {
		count := countIssuesByCheckPrefix(issues, item.prefix)
		if count == 0 {
			continue
		}
		severity := SeverityWarning
		if count >= 2 {
			severity = SeverityCritical
		}
		advisories = append(advisories, Advisory{Title: item.title, Severity: severity, Summary: fmt.Sprintf("%s (%d findings)", item.summary, count), Recommendation: item.rec})
	}
	sortAdvisories(advisories)
	return advisories
}

func BuildSLOInsights(ctx context.Context, cs *kubernetes.Clientset, namespace string, issues []Issue) ([]SLOInsight, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	services, err := cs.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	insights := make([]SLOInsight, 0)
	for _, svc := range services.Items {
		selector := labels.SelectorFromSet(svc.Spec.Selector)
		blastRadius := 0
		if len(svc.Spec.Selector) > 0 {
			pods, podsErr := cs.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 100})
			if podsErr == nil {
				blastRadius = len(pods.Items)
			}
		}
		severity := SeverityInfo
		risk := "low"
		summary := "service has no obvious SLO risk from current findings"
		for _, issue := range issues {
			if issue.Namespace != svc.Namespace {
				continue
			}
			if issue.Kind == "Ingress" || issue.Kind == "Pod" || issue.Kind == "Service" || issue.Check == "ingress-backend-endpoints" || issue.Check == "pod-scheduling" || issue.Check == "crashloop" {
				severity = SeverityWarning
				risk = "medium"
				summary = "workload or edge findings may degrade request success or latency"
			}
			if issue.Severity == SeverityCritical && (issue.Check == "image-pull" || issue.Check == "ingress-backend-endpoints" || issue.Check == "nodes-ready") {
				severity = SeverityCritical
				risk = "high"
				summary = "critical-path findings indicate elevated service availability risk"
			}
		}
		if blastRadius == 0 && severity == SeverityInfo {
			continue
		}
		insights = append(insights, SLOInsight{Service: svc.Name, Namespace: svc.Namespace, Severity: severity, Summary: summary, BlastRadius: blastRadius, Risk: risk})
	}
	sort.SliceStable(insights, func(i, j int) bool {
		if severityRank(insights[i].Severity) != severityRank(insights[j].Severity) {
			return severityRank(insights[i].Severity) > severityRank(insights[j].Severity)
		}
		return insights[i].BlastRadius > insights[j].BlastRadius
	})
	return insights, nil
}

func CompareIssueSets(baseContext, compareContext string, baseIssues, compareIssues []Issue, baseSummaryScore, compareSummaryScore int) ClusterComparison {
	comparison := ClusterComparison{
		BaseContext:    baseContext,
		CompareContext: compareContext,
		BaseScore:      baseSummaryScore,
		CompareScore:   compareSummaryScore,
		CategoryDelta:  map[string]int{},
		SeverityDelta:  map[string]int{},
	}
	baseMap := map[string]Issue{}
	compareMap := map[string]Issue{}
	for _, issue := range baseIssues {
		baseMap[issue.Key()] = issue
		comparison.CategoryDelta[issue.EffectiveCategory()]++
		comparison.SeverityDelta[string(issue.Severity)]++
	}
	for _, issue := range compareIssues {
		compareMap[issue.Key()] = issue
		comparison.CategoryDelta[issue.EffectiveCategory()]--
		comparison.SeverityDelta[string(issue.Severity)]--
	}
	for key, issue := range compareMap {
		if _, ok := baseMap[key]; !ok {
			comparison.NewIssues = append(comparison.NewIssues, issue)
		}
	}
	for key, issue := range baseMap {
		if _, ok := compareMap[key]; !ok {
			comparison.MissingIssues = append(comparison.MissingIssues, issue)
		}
	}
	return comparison
}

func nodePoolName(labelsMap map[string]string) string {
	for _, key := range []string{"agentpool", "eks.amazonaws.com/nodegroup", "cloud.google.com/gke-nodepool", "karpenter.sh/nodepool", "nodepool"} {
		if value := labelsMap[key]; value != "" {
			return value
		}
	}
	return "ungrouped"
}

func ApplyRules(issues []Issue, path string) ([]Issue, []string, error) {
	if strings.TrimSpace(path) == "" {
		return issues, nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var file RuleFile
	if json.Unmarshal(raw, &file) != nil {
		if err := yaml.Unmarshal(raw, &file); err != nil {
			return nil, nil, err
		}
	}
	applied := make([]string, 0)
	out := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		current := issue
		suppressed := false
		for _, rule := range file.Rules {
			if !rule.Match.matches(current) {
				continue
			}
			applied = append(applied, rule.Name)
			if rule.Suppress {
				suppressed = true
				break
			}
			if rule.SetSeverity != "" {
				current.Severity = rule.SetSeverity
			}
			if rule.AddRecommendation != "" {
				current.Recommendation = strings.TrimSpace(current.Recommendation + " " + rule.AddRecommendation)
			}
			if rule.AddReference != "" {
				current.References = append(current.References, rule.AddReference)
			}
			if rule.AppendSummarySuffix != "" {
				current.Summary = strings.TrimSpace(current.Summary + " " + rule.AppendSummarySuffix)
			}
		}
		if !suppressed {
			out = append(out, current)
		}
	}
	if len(applied) == 0 {
		return out, nil, nil
	}
	sort.Strings(applied)
	return out, uniqueStrings(applied), nil
}

func (m RuleMatch) matches(issue Issue) bool {
	if m.Category != "" && issue.EffectiveCategory() != m.Category {
		return false
	}
	if m.Check != "" && issue.Check != m.Check {
		return false
	}
	if m.Kind != "" && issue.Kind != m.Kind {
		return false
	}
	if m.Namespace != "" && issue.Namespace != m.Namespace {
		return false
	}
	if m.Name != "" && issue.Name != m.Name {
		return false
	}
	if m.Severity != "" && issue.Severity != m.Severity {
		return false
	}
	if m.SummaryContains != "" && !strings.Contains(strings.ToLower(issue.Summary), strings.ToLower(m.SummaryContains)) {
		return false
	}
	return true
}

func FilterIssuesByFocus(issues []Issue, focus FocusSpec) []Issue {
	if focus.Value == "" {
		return issues
	}
	filtered := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		if focusMatchesIssue(focus, issue) {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

func focusMatchesIssue(focus FocusSpec, issue Issue) bool {
	value := strings.ToLower(strings.TrimSpace(focus.Value))
	if value == "" {
		return true
	}
	switch strings.ToLower(focus.Kind) {
	case "namespace":
		return strings.EqualFold(issue.Namespace, focus.Value)
	case "node":
		return issue.Kind == "Node" && strings.EqualFold(issue.Name, focus.Value) || strings.Contains(strings.ToLower(issue.Summary), value)
	case "app":
		return strings.Contains(strings.ToLower(issue.Name), value) || strings.Contains(strings.ToLower(issue.Summary), value)
	default:
		return strings.Contains(strings.ToLower(issue.Name), value) || strings.Contains(strings.ToLower(issue.Namespace), value) || strings.Contains(strings.ToLower(issue.Summary), value)
	}
}

func focusMatchesObject(focus FocusSpec, namespace, name string, labelsMap map[string]string, nodeName string) bool {
	value := strings.TrimSpace(focus.Value)
	if value == "" {
		return true
	}
	switch strings.ToLower(focus.Kind) {
	case "namespace":
		return namespace == value
	case "node":
		return nodeName == value || name == value
	case "app":
		if name == value {
			return true
		}
		return labelsMap["app"] == value || labelsMap["app.kubernetes.io/name"] == value
	default:
		return namespace == value || name == value
	}
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func severityRank(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

func severityFromEvent(eventType, reason, message string) Severity {
	text := strings.ToLower(eventType + " " + reason + " " + message)
	if strings.Contains(text, "failed") || strings.Contains(text, "evict") || strings.Contains(text, "backoff") {
		return SeverityWarning
	}
	return SeverityInfo
}

func explanationTitle(key string) string {
	return fmt.Sprintf("%s analysis", strings.ReplaceAll(strings.Title(strings.ReplaceAll(key, "-", " ")), " ", " "))
}

func objectRef(kind, namespace, name string) string {
	if namespace == "" {
		return fmt.Sprintf("%s/%s", kind, name)
	}
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

func dedupeEdges(edges []DependencyEdge) []DependencyEdge {
	if len(edges) == 0 {
		return edges
	}
	seen := map[string]struct{}{}
	out := make([]DependencyEdge, 0, len(edges))
	for _, edge := range edges {
		key := edge.From + "|" + edge.Relation + "|" + edge.To
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, edge)
	}
	return out
}

func countIssuesByCheck(issues []Issue, check string) int {
	count := 0
	for _, issue := range issues {
		if issue.Check == check {
			count++
		}
	}
	return count
}

func countIssuesByCheckPrefix(issues []Issue, prefix string) int {
	count := 0
	for _, issue := range issues {
		if strings.HasPrefix(issue.Check, prefix) {
			count++
		}
	}
	return count
}

func sortAdvisories(advisories []Advisory) {
	sort.SliceStable(advisories, func(i, j int) bool {
		if severityRank(advisories[i].Severity) != severityRank(advisories[j].Severity) {
			return severityRank(advisories[i].Severity) > severityRank(advisories[j].Severity)
		}
		return advisories[i].Title < advisories[j].Title
	})
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeNamespace(namespace string) string {
	if namespace == "" {
		return metav1.NamespaceAll
	}
	return namespace
}

func defaultNamespace(namespace string) string {
	if namespace == "" {
		return "default"
	}
	return namespace
}

func BuildControllerDependencyEdges(ctx context.Context, cs *kubernetes.Clientset, namespace string, focus FocusSpec) ([]DependencyEdge, error) {
	if cs == nil {
		return nil, nil
	}
	ns := normalizeNamespace(namespace)
	edges := make([]DependencyEdge, 0)
	deployments, err := cs.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, deployment := range deployments.Items {
		if !focusMatchesObject(focus, deployment.Namespace, deployment.Name, deployment.Labels, "") {
			continue
		}
		edges = append(edges, edgesForController(ctx, cs, deployment)...)
	}
	return edges, nil
}

func edgesForController(ctx context.Context, cs *kubernetes.Clientset, deployment appsv1.Deployment) []DependencyEdge {
	if deployment.Spec.Selector == nil {
		return nil
	}
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return nil
	}
	pods, err := cs.CoreV1().Pods(deployment.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
	if err != nil {
		return nil
	}
	edges := make([]DependencyEdge, 0, len(pods.Items))
	for _, pod := range pods.Items {
		edges = append(edges, DependencyEdge{From: objectRef("Deployment", deployment.Namespace, deployment.Name), To: objectRef("Pod", pod.Namespace, pod.Name), Relation: "owns"})
	}
	return edges
}

func EvaluatePDBUpgradeImpact(pdbs []policyv1.PodDisruptionBudget) int {
	blocked := 0
	for _, pdb := range pdbs {
		if pdb.Status.DisruptionsAllowed == 0 && pdb.Status.ExpectedPods > 0 {
			blocked++
		}
	}
	return blocked
}

func IngressBackends(ing networkingv1.Ingress) []string {
	backends := make([]string, 0)
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				backends = append(backends, path.Backend.Service.Name)
			}
		}
	}
	return uniqueStrings(backends)
}
