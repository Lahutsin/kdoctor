package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"k8doc/internal/diagnostics"
)

func main() {
	var kubeconfig string
	var namespace string
	var kubeContext string
	var checks string
	var timeoutSec int
	var output string
	var failOn string
	var baselinePath string
	var writeBaselinePath string
	var mode string
	var focusKind string
	var focusValue string
	var profile string
	var rulesPath string
	var reportPath string
	var reportFormat string
	var timelineLimit int
	var compareContext string
	var compareKubeconfig string
	var suppressNoise bool

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config)")
	flag.StringVar(&namespace, "namespace", "", "Namespace to inspect (empty for all)")
	flag.StringVar(&kubeContext, "context", "", "Kubeconfig context to use")
	flag.StringVar(&checks, "checks", defaultChecks(), "Comma-separated checks to run")
	flag.IntVar(&timeoutSec, "timeout", 30, "Overall timeout in seconds for all checks")
	flag.StringVar(&output, "output", "table", "Output format: table or json")
	flag.StringVar(&failOn, "fail-on", "", "Exit with code 2 if any issue meets or exceeds this severity: info, warning, critical")
	flag.StringVar(&baselinePath, "baseline", "", "Path to a previously saved JSON baseline file for diffing")
	flag.StringVar(&writeBaselinePath, "write-baseline", "", "Path to write the current scan as a JSON baseline snapshot")
	flag.StringVar(&mode, "mode", "scan", "Mode: scan, incident, explain, diff, timeline, dependencies, service-view, node-pool-view, network-path, storage-path, release-readiness, upgrade-readiness, security, cost, slo, remediation, multi-cluster-compare, full")
	flag.StringVar(&focusKind, "focus-kind", "", "Focus type: namespace, app, node, service, node-pool")
	flag.StringVar(&focusValue, "focus", "", "Focus value used to narrow issues and analysis views")
	flag.StringVar(&profile, "profile", "", "Profile preset: quick, prod, pre-upgrade, network, storage, admission, cost, ci")
	flag.StringVar(&rulesPath, "rules", "", "Path to a YAML or JSON rules file for severity overrides or suppression")
	flag.StringVar(&reportPath, "report", "", "Write a markdown or html report to this path")
	flag.StringVar(&reportFormat, "report-format", "markdown", "Report format: markdown or html")
	flag.IntVar(&timelineLimit, "timeline-limit", 20, "Maximum number of timeline entries to return")
	flag.StringVar(&compareContext, "compare-context", "", "Secondary kubeconfig context used for multi-cluster comparison")
	flag.StringVar(&compareKubeconfig, "compare-kubeconfig", "", "Optional kubeconfig path for the secondary comparison context")
	flag.BoolVar(&suppressNoise, "suppress-noise", true, "Suppress built-in non-actionable informational findings")
	flag.Parse()

	applyProfile(&checks, &output, &failOn, &mode, profile)
	if focusKind == "namespace" && namespace == "" && focusValue != "" {
		namespace = focusValue
	}

	if kubeconfig == "" {
		kubeconfig = diagnostics.DefaultKubeconfig()
	}

	checker, err := diagnostics.NewChecker(kubeconfig, kubeContext, namespace, parseChecks(checks), time.Duration(timeoutSec)*time.Second)
	if err != nil {
		fatalf("init client: %v", err)
	}

	issues, err := checker.Run(context.Background())
	if err != nil {
		fatalf("run checks: %v", err)
	}
	issues, appliedRules, err := diagnostics.ApplyRules(issues, rulesPath)
	if err != nil {
		fatalf("apply rules: %v", err)
	}
	issues, suppressedNoise := diagnostics.ApplyBuiltInNoiseSuppression(issues, suppressNoise)

	focus := diagnostics.FocusSpec{Kind: focusKind, Value: focusValue}
	issues = diagnostics.FilterIssuesByFocus(issues, focus)
	if mode == "incident" {
		issues = diagnostics.FilterIncidentIssues(issues)
	}
	sortIssues(issues)
	summary := buildHealthSummary(issues)

	report, err := composeReport(context.Background(), checker, summary, issues, reportOptions{
		Mode:              mode,
		Profile:           profile,
		Output:            output,
		FailOn:            failOn,
		BaselinePath:      baselinePath,
		WriteBaselinePath: writeBaselinePath,
		Focus:             focus,
		TimelineLimit:     timelineLimit,
		AppliedRules:      append(appliedRules, suppressedNoise...),
	})
	if err != nil {
		fatalf("compose report: %v", err)
	}

	if mode == "multi-cluster-compare" && compareContext != "" {
		comparison, err := buildComparisonReport(compareInput{
			BaseKubeconfig:    kubeconfig,
			BaseContext:       kubeContext,
			CompareKubeconfig: compareKubeconfig,
			CompareContext:    compareContext,
			Namespace:         namespace,
			Checks:            checks,
			Timeout:           time.Duration(timeoutSec) * time.Second,
			RulesPath:         rulesPath,
			Focus:             focus,
			SuppressNoise:     suppressNoise,
			CurrentIssues:     report.Issues,
			CurrentScore:      report.Summary.Score,
		})
		if err != nil {
			fatalf("compare clusters: %v", err)
		}
		report.Comparison = comparison
	}

	if reportPath != "" {
		if err := writeRenderedReport(reportPath, reportFormat, report); err != nil {
			fatalf("write report: %v", err)
		}
	}

	if output == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fatalf("encode json: %v", err)
		}
	} else {
		renderMode(report)
	}

	if report.Options.FailOn != "" && meetsFailThreshold(report.Issues, report.Options.FailOn) {
		os.Exit(2)
	}
}

type categorySummary struct {
	Category string `json:"category"`
	Score    int    `json:"score"`
	Critical int    `json:"critical"`
	Warning  int    `json:"warning"`
	Info     int    `json:"info"`
}

type healthSummary struct {
	Score      int               `json:"score"`
	Critical   int               `json:"critical"`
	Warning    int               `json:"warning"`
	Info       int               `json:"info"`
	Categories []categorySummary `json:"categories"`
}

type baselineDiff struct {
	NewCount      int                 `json:"newCount"`
	ResolvedCount int                 `json:"resolvedCount"`
	WorsenedCount int                 `json:"worsenedCount"`
	NewIssues     []diagnostics.Issue `json:"newIssues,omitempty"`
	Resolved      []diagnostics.Issue `json:"resolved,omitempty"`
	Worsened      []diagnostics.Issue `json:"worsened,omitempty"`
}

type reportOptions struct {
	Mode              string                `json:"mode"`
	Profile           string                `json:"profile,omitempty"`
	Output            string                `json:"output"`
	FailOn            string                `json:"failOn,omitempty"`
	BaselinePath      string                `json:"baselinePath,omitempty"`
	WriteBaselinePath string                `json:"writeBaselinePath,omitempty"`
	Focus             diagnostics.FocusSpec `json:"focus,omitempty"`
	TimelineLimit     int                   `json:"timelineLimit,omitempty"`
	AppliedRules      []string              `json:"appliedRules,omitempty"`
}

type scanReport struct {
	GeneratedAt      time.Time                      `json:"generatedAt"`
	Summary          healthSummary                  `json:"summary"`
	Issues           []diagnostics.Issue            `json:"issues"`
	Baseline         *baselineDiff                  `json:"baseline,omitempty"`
	Explanations     []diagnostics.Explanation      `json:"explanations,omitempty"`
	Timeline         []diagnostics.TimelineEntry    `json:"timeline,omitempty"`
	Dependencies     []diagnostics.DependencyEdge   `json:"dependencies,omitempty"`
	ServiceViews     []diagnostics.ServiceView      `json:"serviceViews,omitempty"`
	NodePoolViews    []diagnostics.NodePoolView     `json:"nodePoolViews,omitempty"`
	NetworkPaths     []diagnostics.PathResult       `json:"networkPaths,omitempty"`
	StoragePaths     []diagnostics.PathResult       `json:"storagePaths,omitempty"`
	ReleaseReadiness []diagnostics.Advisory         `json:"releaseReadiness,omitempty"`
	UpgradeReadiness []diagnostics.Advisory         `json:"upgradeReadiness,omitempty"`
	SecurityPosture  []diagnostics.Advisory         `json:"securityPosture,omitempty"`
	CostWaste        []diagnostics.Advisory         `json:"costWaste,omitempty"`
	SLOInsights      []diagnostics.SLOInsight       `json:"sloInsights,omitempty"`
	Remediations     []diagnostics.RemediationStep  `json:"remediations,omitempty"`
	Comparison       *diagnostics.ClusterComparison `json:"comparison,omitempty"`
	Options          reportOptions                  `json:"options"`
}

type compareInput struct {
	BaseKubeconfig    string
	BaseContext       string
	CompareKubeconfig string
	CompareContext    string
	Namespace         string
	Checks            string
	Timeout           time.Duration
	RulesPath         string
	Focus             diagnostics.FocusSpec
	SuppressNoise     bool
	CurrentIssues     []diagnostics.Issue
	CurrentScore      int
}

func composeReport(ctx context.Context, checker *diagnostics.Checker, summary healthSummary, issues []diagnostics.Issue, opts reportOptions) (scanReport, error) {
	report := scanReport{
		GeneratedAt: time.Now().UTC(),
		Summary:     summary,
		Issues:      issues,
		Options:     opts,
	}

	if opts.BaselinePath != "" {
		diff, err := loadAndCompareBaseline(opts.BaselinePath, issues)
		if err != nil {
			return report, err
		}
		report.Baseline = diff
	}

	namespace := checker.NamespaceScope()
	if opts.Focus.Kind == "namespace" && opts.Focus.Value != "" {
		namespace = opts.Focus.Value
	}

	buildAll := opts.Mode == "full" || (opts.Mode == "scan" && opts.Output == "json") || opts.WriteBaselinePath != "" || opts.Profile == "ci"
	need := func(section string) bool {
		return buildAll || opts.Mode == section || opts.Mode == "full"
	}

	if need("explain") {
		report.Explanations = diagnostics.BuildExplanations(issues)
	}
	if need("timeline") {
		timeline, err := diagnostics.BuildTimeline(ctx, checker.Clientset(), namespace, opts.TimelineLimit)
		if err != nil {
			return report, err
		}
		report.Timeline = timeline
	}
	if need("dependencies") {
		deps, err := diagnostics.BuildDependencies(ctx, checker.Clientset(), namespace, opts.Focus)
		if err != nil {
			return report, err
		}
		controllerDeps, err := diagnostics.BuildControllerDependencyEdges(ctx, checker.Clientset(), namespace, opts.Focus)
		if err == nil {
			deps = append(deps, controllerDeps...)
		}
		report.Dependencies = deps
	}
	if need("service-view") {
		serviceName := ""
		if opts.Focus.Kind == "service" {
			serviceName = opts.Focus.Value
		}
		views, err := diagnostics.BuildServiceViews(ctx, checker.Clientset(), namespace, serviceName)
		if err != nil {
			return report, err
		}
		report.ServiceViews = views
	}
	if need("node-pool-view") {
		views, err := diagnostics.BuildNodePoolViews(ctx, checker.Clientset(), issues)
		if err != nil {
			return report, err
		}
		report.NodePoolViews = views
	}
	if need("network-path") {
		paths, err := diagnostics.BuildNetworkPaths(ctx, checker.Clientset(), namespace, opts.Focus)
		if err != nil {
			return report, err
		}
		report.NetworkPaths = paths
	}
	if need("storage-path") {
		paths, err := diagnostics.BuildStoragePaths(ctx, checker.Clientset(), namespace, opts.Focus)
		if err != nil {
			return report, err
		}
		report.StoragePaths = paths
	}
	if need("release-readiness") {
		report.ReleaseReadiness = diagnostics.EvaluateReleaseReadiness(issues)
	}
	if need("upgrade-readiness") {
		advisories, err := diagnostics.EvaluateUpgradeReadiness(ctx, checker.Clientset(), namespace, issues)
		if err != nil {
			return report, err
		}
		report.UpgradeReadiness = advisories
	}
	if need("security") {
		advisories, err := diagnostics.EvaluateSecurityPosture(ctx, checker.Clientset(), namespace, issues)
		if err != nil {
			return report, err
		}
		report.SecurityPosture = advisories
	}
	if need("cost") {
		advisories, err := diagnostics.EvaluateCostWaste(ctx, checker.Clientset(), namespace, issues)
		if err != nil {
			return report, err
		}
		report.CostWaste = advisories
	}
	if need("slo") {
		insights, err := diagnostics.BuildSLOInsights(ctx, checker.Clientset(), namespace, issues)
		if err != nil {
			return report, err
		}
		report.SLOInsights = insights
	}
	if need("remediation") {
		report.Remediations = diagnostics.BuildRemediations(issues)
	}

	if opts.WriteBaselinePath != "" {
		if err := writeBaseline(opts.WriteBaselinePath, report); err != nil {
			return report, err
		}
	}

	return report, nil
}

func defaultChecks() string {
	return "pods,gpu,runtimebehavior,podsecurity,secrets,configexposure,networksecurity,storagesecurity,multitenancy,managedk8s,observability,policy,nodes,events,controllers,apiserver,rbac,serviceaccounts,webhooks,cni,controlplane,dns,storage,certificates,quotas,ingress,autoscaling,pdb,scheduling,trends"
}

func applyProfile(checks, output, failOn, mode *string, profile string) {
	switch strings.TrimSpace(profile) {
	case "quick":
		*checks = "pods,nodes,events,apiserver"
	case "prod":
		*checks = defaultChecks()
		if *failOn == "" {
			*failOn = "critical"
		}
	case "pre-upgrade":
		*checks = defaultChecks()
		*mode = "upgrade-readiness"
	case "network":
		*checks = "nodes,dns,ingress,cni,webhooks,events,scheduling"
		*mode = "network-path"
	case "incident":
		*checks = "pods,gpu,nodes,apiserver,controlplane,dns,cni,ingress,webhooks,storage,events"
		*mode = "incident"
		if *failOn == "" {
			*failOn = "warning"
		}
	case "release":
		*checks = "quotas,pdb,pods,webhooks,ingress,autoscaling,storage,events"
		*mode = "release-readiness"
	case "storage":
		*checks = "storage,pods,cni,events"
		*mode = "storage-path"
	case "admission":
		*checks = "webhooks,certificates,apiserver,events"
		*mode = "security"
	case "cost":
		*checks = "controllers,storage,autoscaling,quotas,ingress"
		*mode = "cost"
	case "ci":
		*checks = defaultChecks()
		*output = "json"
		if *failOn == "" {
			*failOn = "warning"
		}
		if *mode == "scan" {
			*mode = "full"
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func sortIssues(issues []diagnostics.Issue) {
	weight := map[diagnostics.Severity]int{
		diagnostics.SeverityCritical: 0,
		diagnostics.SeverityWarning:  1,
		diagnostics.SeverityInfo:     2,
	}
	sort.SliceStable(issues, func(i, j int) bool {
		wi := weight[issues[i].Severity]
		wj := weight[issues[j].Severity]
		if wi != wj {
			return wi < wj
		}
		if issues[i].Namespace != issues[j].Namespace {
			return issues[i].Namespace < issues[j].Namespace
		}
		return issues[i].Summary < issues[j].Summary
	})
}

func parseChecks(csv string) map[string]bool {
	result := map[string]bool{}
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		result[p] = true
	}
	return result
}

func buildHealthSummary(issues []diagnostics.Issue) healthSummary {
	counts := map[string]*categorySummary{}
	summary := healthSummary{}
	for _, issue := range issues {
		category := issue.EffectiveCategory()
		bucket := counts[category]
		if bucket == nil {
			bucket = &categorySummary{Category: category, Score: 100}
			counts[category] = bucket
		}
		switch issue.Severity {
		case diagnostics.SeverityCritical:
			summary.Critical++
			bucket.Critical++
		case diagnostics.SeverityWarning:
			summary.Warning++
			bucket.Warning++
		default:
			summary.Info++
			bucket.Info++
		}
	}
	summary.Score = clampScore(100 - summary.Critical*20 - summary.Warning*8 - summary.Info*2)
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		bucket := counts[key]
		bucket.Score = clampScore(100 - bucket.Critical*20 - bucket.Warning*8 - bucket.Info*2)
		summary.Categories = append(summary.Categories, *bucket)
	}
	if len(summary.Categories) == 0 {
		summary.Categories = []categorySummary{}
	}
	return summary
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func renderMode(report scanReport) {
	renderSummary(report.Summary, report.Baseline, report.Options)
	switch report.Options.Mode {
	case "explain":
		renderExplanations(report.Explanations)
		renderTable(report.Issues)
	case "incident":
		renderTable(report.Issues)
	case "diff":
		renderDiff(report.Baseline)
	case "timeline":
		renderTimeline(report.Timeline)
	case "dependencies":
		renderDependencies(report.Dependencies)
	case "service-view":
		renderServiceViews(report.ServiceViews)
	case "node-pool-view":
		renderNodePoolViews(report.NodePoolViews)
	case "network-path":
		renderPaths("Network Paths", report.NetworkPaths)
	case "storage-path":
		renderPaths("Storage Paths", report.StoragePaths)
	case "release-readiness":
		renderAdvisories("Release Readiness", report.ReleaseReadiness)
	case "upgrade-readiness":
		renderAdvisories("Upgrade Readiness", report.UpgradeReadiness)
	case "security":
		renderAdvisories("Security Posture", report.SecurityPosture)
	case "cost":
		renderAdvisories("Cost Waste", report.CostWaste)
	case "slo":
		renderSLOInsights(report.SLOInsights)
	case "remediation":
		renderRemediations(report.Remediations)
	case "multi-cluster-compare":
		renderComparison(report.Comparison)
	case "full":
		renderExplanations(report.Explanations)
		renderDiff(report.Baseline)
		renderTimeline(report.Timeline)
		renderDependencies(report.Dependencies)
		renderServiceViews(report.ServiceViews)
		renderNodePoolViews(report.NodePoolViews)
		renderPaths("Network Paths", report.NetworkPaths)
		renderPaths("Storage Paths", report.StoragePaths)
		renderAdvisories("Release Readiness", report.ReleaseReadiness)
		renderAdvisories("Upgrade Readiness", report.UpgradeReadiness)
		renderAdvisories("Security Posture", report.SecurityPosture)
		renderAdvisories("Cost Waste", report.CostWaste)
		renderSLOInsights(report.SLOInsights)
		renderComparison(report.Comparison)
		renderRemediations(report.Remediations)
		renderTable(report.Issues)
	default:
		if len(report.Issues) == 0 {
			fmt.Println("No obvious issues detected. Cluster looks healthy from the inspected signals.")
			return
		}
		renderTable(report.Issues)
	}
}

func renderSummary(summary healthSummary, diff *baselineDiff, opts reportOptions) {
	fmt.Printf("Health score: %d/100 | critical=%d warning=%d info=%d\n", summary.Score, summary.Critical, summary.Warning, summary.Info)
	if diff != nil {
		fmt.Printf("Diff: new=%d resolved=%d worsened=%d\n", diff.NewCount, diff.ResolvedCount, diff.WorsenedCount)
	}
	if opts.Focus.Value != "" {
		fmt.Printf("Focus: %s=%s\n", opts.Focus.Kind, opts.Focus.Value)
	}
	if len(opts.AppliedRules) > 0 {
		fmt.Printf("Rules: %s\n", strings.Join(opts.AppliedRules, ", "))
	}
	parts := make([]string, 0, len(summary.Categories))
	for _, category := range summary.Categories {
		parts = append(parts, fmt.Sprintf("%s=%d", category.Category, category.Score))
	}
	if len(parts) > 0 {
		fmt.Printf("Category scores: %s\n\n", strings.Join(parts, ", "))
	} else {
		fmt.Println()
	}
}

func renderTable(issues []diagnostics.Issue) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tOBJECT\tSUMMARY\tRECOMMENDATION")
	for _, issue := range issues {
		object := issue.Kind
		switch {
		case issue.Namespace != "" && issue.Name != "":
			object = fmt.Sprintf("%s/%s/%s", issue.Kind, issue.Namespace, issue.Name)
		case issue.Name != "":
			object = fmt.Sprintf("%s/%s", issue.Kind, issue.Name)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", strings.ToUpper(string(issue.Severity)), object, issue.Summary, issue.Recommendation)
		if len(issue.References) > 0 {
			fmt.Fprintf(w, "\t\tRefs: %s\n", strings.Join(issue.References, ", "))
		}
	}
	_ = w.Flush()
}

func renderExplanations(explanations []diagnostics.Explanation) {
	if len(explanations) == 0 {
		return
	}
	fmt.Println("Explanations:")
	for _, explanation := range explanations {
		fmt.Printf("- [%s] %s: %s\n", strings.ToUpper(string(explanation.Severity)), explanation.Title, explanation.Summary)
	}
	fmt.Println()
}

func renderDiff(diff *baselineDiff) {
	if diff == nil {
		fmt.Println("Diff: no baseline provided")
		fmt.Println()
		return
	}
	fmt.Println("Diff:")
	fmt.Printf("- New issues: %d\n", diff.NewCount)
	fmt.Printf("- Resolved issues: %d\n", diff.ResolvedCount)
	fmt.Printf("- Worsened issues: %d\n", diff.WorsenedCount)
	fmt.Println()
}

func renderTimeline(entries []diagnostics.TimelineEntry) {
	if len(entries) == 0 {
		return
	}
	fmt.Println("Timeline:")
	for _, entry := range entries {
		fmt.Printf("- %s [%s] %s/%s %s: %s\n", entry.Time.Format(time.RFC3339), strings.ToUpper(string(entry.Severity)), entry.Kind, entry.Name, entry.Reason, entry.Message)
	}
	fmt.Println()
}

func renderDependencies(edges []diagnostics.DependencyEdge) {
	if len(edges) == 0 {
		return
	}
	fmt.Println("Dependencies:")
	for _, edge := range edges {
		fmt.Printf("- %s %s %s\n", edge.From, edge.Relation, edge.To)
	}
	fmt.Println()
}

func renderServiceViews(views []diagnostics.ServiceView) {
	if len(views) == 0 {
		return
	}
	fmt.Println("Service Views:")
	for _, view := range views {
		fmt.Printf("- %s/%s: %s\n", view.Namespace, view.Name, strings.Join(view.Chain, " -> "))
		for _, finding := range view.Findings {
			fmt.Printf("  %s\n", finding)
		}
	}
	fmt.Println()
}

func renderNodePoolViews(views []diagnostics.NodePoolView) {
	if len(views) == 0 {
		return
	}
	fmt.Println("Node Pool Views:")
	for _, view := range views {
		fmt.Printf("- %s: nodes=%d severities=%s\n", view.Name, view.NodeCount, strings.Join(view.Severities, ", "))
		for _, finding := range view.Findings {
			fmt.Printf("  %s\n", finding)
		}
	}
	fmt.Println()
}

func renderPaths(title string, paths []diagnostics.PathResult) {
	if len(paths) == 0 {
		return
	}
	fmt.Printf("%s:\n", title)
	for _, path := range paths {
		fmt.Printf("- %s: %s\n", path.Name, strings.Join(path.Steps, " -> "))
		for _, finding := range path.Findings {
			fmt.Printf("  %s\n", finding)
		}
	}
	fmt.Println()
}

func renderAdvisories(title string, advisories []diagnostics.Advisory) {
	if len(advisories) == 0 {
		return
	}
	fmt.Printf("%s:\n", title)
	for _, advisory := range advisories {
		fmt.Printf("- [%s] %s: %s\n", strings.ToUpper(string(advisory.Severity)), advisory.Title, advisory.Summary)
	}
	fmt.Println()
}

func renderSLOInsights(insights []diagnostics.SLOInsight) {
	if len(insights) == 0 {
		return
	}
	fmt.Println("SLO Insights:")
	for _, insight := range insights {
		fmt.Printf("- [%s] %s/%s blastRadius=%d risk=%s: %s\n", strings.ToUpper(string(insight.Severity)), insight.Namespace, insight.Service, insight.BlastRadius, insight.Risk, insight.Summary)
	}
	fmt.Println()
}

func renderComparison(comparison *diagnostics.ClusterComparison) {
	if comparison == nil {
		return
	}
	fmt.Println("Cluster Comparison:")
	fmt.Printf("- %s score=%d vs %s score=%d\n", comparison.BaseContext, comparison.BaseScore, comparison.CompareContext, comparison.CompareScore)
	fmt.Printf("- new issues in compare: %d\n", len(comparison.NewIssues))
	fmt.Printf("- issues missing in compare: %d\n", len(comparison.MissingIssues))
	fmt.Println()
}

func renderRemediations(steps []diagnostics.RemediationStep) {
	if len(steps) == 0 {
		return
	}
	fmt.Println("Remediation:")
	for _, step := range steps {
		fmt.Printf("- %s\n  %s\n", step.Title, step.Command)
	}
	fmt.Println()
}

func loadAndCompareBaseline(path string, current []diagnostics.Issue) (*baselineDiff, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var previous scanReport
	if err := json.Unmarshal(raw, &previous); err != nil {
		return nil, err
	}
	prevMap := make(map[string]diagnostics.Issue, len(previous.Issues))
	for _, issue := range previous.Issues {
		prevMap[issue.Key()] = issue
	}
	curMap := make(map[string]diagnostics.Issue, len(current))
	for _, issue := range current {
		curMap[issue.Key()] = issue
	}
	diff := &baselineDiff{}
	for key, issue := range curMap {
		prev, ok := prevMap[key]
		if !ok {
			diff.NewCount++
			diff.NewIssues = append(diff.NewIssues, issue)
			continue
		}
		if severityWeight(issue.Severity) > severityWeight(prev.Severity) {
			diff.WorsenedCount++
			diff.Worsened = append(diff.Worsened, issue)
		}
	}
	for key, issue := range prevMap {
		if _, ok := curMap[key]; !ok {
			diff.ResolvedCount++
			diff.Resolved = append(diff.Resolved, issue)
		}
	}
	return diff, nil
}

func writeBaseline(path string, report scanReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeRenderedReport(path, format string, report scanReport) error {
	var body string
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "html":
		body = renderHTMLReport(report)
	default:
		body = renderMarkdownReport(report)
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

func renderMarkdownReport(report scanReport) string {
	var builder strings.Builder
	builder.WriteString("# k8doc report\n\n")
	builder.WriteString(fmt.Sprintf("Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("Health score: %d/100\n\n", report.Summary.Score))
	if report.Options.Focus.Value != "" {
		builder.WriteString(fmt.Sprintf("Focus: %s=%s\n\n", report.Options.Focus.Kind, report.Options.Focus.Value))
	}
	if len(report.Explanations) > 0 {
		builder.WriteString("## Explain\n")
		for _, item := range report.Explanations {
			builder.WriteString(fmt.Sprintf("- [%s] %s: %s\n", strings.ToUpper(string(item.Severity)), item.Title, item.Summary))
		}
		builder.WriteString("\n")
	}
	if report.Baseline != nil {
		builder.WriteString("## Diff\n")
		builder.WriteString(fmt.Sprintf("- New: %d\n- Resolved: %d\n- Worsened: %d\n\n", report.Baseline.NewCount, report.Baseline.ResolvedCount, report.Baseline.WorsenedCount))
	}
	if len(report.Timeline) > 0 {
		builder.WriteString("## Timeline\n")
		for _, entry := range report.Timeline {
			builder.WriteString(fmt.Sprintf("- %s [%s] %s/%s %s\n", entry.Time.Format(time.RFC3339), strings.ToUpper(string(entry.Severity)), entry.Kind, entry.Name, entry.Message))
		}
		builder.WriteString("\n")
	}
	writeEdgesMarkdown(&builder, "Dependencies", report.Dependencies)
	writeServiceViewsMarkdown(&builder, report.ServiceViews)
	writeNodePoolsMarkdown(&builder, report.NodePoolViews)
	writePathsMarkdown(&builder, "Network Paths", report.NetworkPaths)
	writePathsMarkdown(&builder, "Storage Paths", report.StoragePaths)
	writeAdvisoriesMarkdown(&builder, "Release Readiness", report.ReleaseReadiness)
	writeAdvisoriesMarkdown(&builder, "Upgrade Readiness", report.UpgradeReadiness)
	writeAdvisoriesMarkdown(&builder, "Security Posture", report.SecurityPosture)
	writeAdvisoriesMarkdown(&builder, "Cost Waste", report.CostWaste)
	writeSLOMarkdown(&builder, report.SLOInsights)
	writeComparisonMarkdown(&builder, report.Comparison)
	if len(report.Remediations) > 0 {
		builder.WriteString("## Remediation\n")
		for _, step := range report.Remediations {
			builder.WriteString(fmt.Sprintf("- %s\n\n```bash\n%s\n```\n", step.Title, step.Command))
		}
	}
	if len(report.Issues) > 0 {
		builder.WriteString("## Issues\n")
		for _, issue := range report.Issues {
			builder.WriteString(fmt.Sprintf("- [%s] %s/%s %s\n", strings.ToUpper(string(issue.Severity)), issue.Kind, issue.Name, issue.Summary))
		}
	}
	return builder.String()
}

func renderHTMLReport(report scanReport) string {
	markdown := renderMarkdownReport(report)
	return "<!doctype html><html><head><meta charset=\"utf-8\"><title>k8doc report</title><style>body{font-family:ui-monospace,Menlo,monospace;max-width:960px;margin:40px auto;padding:0 24px;line-height:1.5}pre{background:#f6f8fa;padding:12px;overflow:auto}code{font-family:inherit}</style></head><body><pre>" + html.EscapeString(markdown) + "</pre></body></html>"
}

func writeEdgesMarkdown(builder *strings.Builder, title string, edges []diagnostics.DependencyEdge) {
	if len(edges) == 0 {
		return
	}
	builder.WriteString("## " + title + "\n")
	for _, edge := range edges {
		builder.WriteString(fmt.Sprintf("- %s %s %s\n", edge.From, edge.Relation, edge.To))
	}
	builder.WriteString("\n")
}

func writePathsMarkdown(builder *strings.Builder, title string, paths []diagnostics.PathResult) {
	if len(paths) == 0 {
		return
	}
	builder.WriteString("## " + title + "\n")
	for _, path := range paths {
		builder.WriteString(fmt.Sprintf("- %s: %s\n", path.Name, strings.Join(path.Steps, " -> ")))
		for _, finding := range path.Findings {
			builder.WriteString(fmt.Sprintf("  - %s\n", finding))
		}
	}
	builder.WriteString("\n")
}

func writeServiceViewsMarkdown(builder *strings.Builder, views []diagnostics.ServiceView) {
	if len(views) == 0 {
		return
	}
	builder.WriteString("## Service Views\n")
	for _, view := range views {
		builder.WriteString(fmt.Sprintf("- %s/%s: %s\n", view.Namespace, view.Name, strings.Join(view.Chain, " -> ")))
	}
	builder.WriteString("\n")
}

func writeNodePoolsMarkdown(builder *strings.Builder, views []diagnostics.NodePoolView) {
	if len(views) == 0 {
		return
	}
	builder.WriteString("## Node Pool Views\n")
	for _, view := range views {
		builder.WriteString(fmt.Sprintf("- %s: nodes=%d severities=%s\n", view.Name, view.NodeCount, strings.Join(view.Severities, ", ")))
	}
	builder.WriteString("\n")
}

func writeAdvisoriesMarkdown(builder *strings.Builder, title string, advisories []diagnostics.Advisory) {
	if len(advisories) == 0 {
		return
	}
	builder.WriteString("## " + title + "\n")
	for _, advisory := range advisories {
		builder.WriteString(fmt.Sprintf("- [%s] %s: %s\n", strings.ToUpper(string(advisory.Severity)), advisory.Title, advisory.Summary))
	}
	builder.WriteString("\n")
}

func writeSLOMarkdown(builder *strings.Builder, insights []diagnostics.SLOInsight) {
	if len(insights) == 0 {
		return
	}
	builder.WriteString("## SLO Insights\n")
	for _, insight := range insights {
		builder.WriteString(fmt.Sprintf("- [%s] %s/%s blastRadius=%d risk=%s %s\n", strings.ToUpper(string(insight.Severity)), insight.Namespace, insight.Service, insight.BlastRadius, insight.Risk, insight.Summary))
	}
	builder.WriteString("\n")
}

func writeComparisonMarkdown(builder *strings.Builder, comparison *diagnostics.ClusterComparison) {
	if comparison == nil {
		return
	}
	builder.WriteString("## Cluster Comparison\n")
	builder.WriteString(fmt.Sprintf("- %s score=%d\n- %s score=%d\n- new issues=%d\n- missing issues=%d\n\n", comparison.BaseContext, comparison.BaseScore, comparison.CompareContext, comparison.CompareScore, len(comparison.NewIssues), len(comparison.MissingIssues)))
}

func buildComparisonReport(input compareInput) (*diagnostics.ClusterComparison, error) {
	compareKubeconfig := input.CompareKubeconfig
	if compareKubeconfig == "" {
		compareKubeconfig = input.BaseKubeconfig
	}
	checker, err := diagnostics.NewChecker(compareKubeconfig, input.CompareContext, input.Namespace, parseChecks(input.Checks), input.Timeout)
	if err != nil {
		return nil, err
	}
	issues, err := checker.Run(context.Background())
	if err != nil {
		return nil, err
	}
	issues, _, err = diagnostics.ApplyRules(issues, input.RulesPath)
	if err != nil {
		return nil, err
	}
	issues, _ = diagnostics.ApplyBuiltInNoiseSuppression(issues, input.SuppressNoise)
	issues = diagnostics.FilterIssuesByFocus(issues, input.Focus)
	if input.Focus.Kind == "" && input.Namespace == "" {
		issues = issues
	}
	sortIssues(issues)
	compareSummary := buildHealthSummary(issues)
	comparison := diagnostics.CompareIssueSets(input.BaseContext, input.CompareContext, input.CurrentIssues, issues, input.CurrentScore, compareSummary.Score)
	return &comparison, nil
}

func meetsFailThreshold(issues []diagnostics.Issue, failOn string) bool {
	if failOn == "" {
		return false
	}
	weights := map[string]int{"info": 1, "warning": 2, "critical": 3}
	threshold, ok := weights[strings.ToLower(strings.TrimSpace(failOn))]
	if !ok {
		fatalf("invalid fail-on value %q, expected one of: info, warning, critical", failOn)
	}
	for _, issue := range issues {
		if severityWeight(issue.Severity) >= threshold {
			return true
		}
	}
	return false
}

func severityWeight(sev diagnostics.Severity) int {
	switch sev {
	case diagnostics.SeverityCritical:
		return 3
	case diagnostics.SeverityWarning:
		return 2
	default:
		return 1
	}
}
