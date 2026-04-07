package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kdoctor/internal/diagnostics"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer

	defer func() {
		os.Stdout = oldStdout
	}()

	fn()
	_ = writer.Close()

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(output)
}

func sampleIssues() []diagnostics.Issue {
	return []diagnostics.Issue{
		{
			Kind:           "Pod",
			Namespace:      "ns-b",
			Name:           "pod-b",
			Severity:       diagnostics.SeverityInfo,
			Check:          "pods",
			Summary:        "pod informational",
			Recommendation: "inspect pod",
			References:     []string{"runbook/pod"},
		},
		{
			Kind:           "Node",
			Namespace:      "",
			Name:           "node-a",
			Severity:       diagnostics.SeverityCritical,
			Check:          "nodes",
			Summary:        "node critical",
			Recommendation: "cordon node",
		},
		{
			Kind:           "Deployment",
			Namespace:      "ns-a",
			Name:           "deploy-a",
			Severity:       diagnostics.SeverityWarning,
			Check:          "controllers",
			Summary:        "deployment warning",
			Recommendation: "rollout restart",
		},
	}
}

func sampleReport() scanReport {
	timestamp := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	issues := sampleIssues()
	return scanReport{
		GeneratedAt: timestamp,
		Summary:     buildHealthSummary(issues),
		Issues:      issues,
		Baseline: &baselineDiff{
			NewCount:      1,
			ResolvedCount: 2,
			WorsenedCount: 1,
		},
		Explanations: []diagnostics.Explanation{{
			Title:    "Pods",
			Severity: diagnostics.SeverityWarning,
			Summary:  "workload instability",
		}},
		Timeline: []diagnostics.TimelineEntry{{
			Time:     timestamp,
			Severity: diagnostics.SeverityWarning,
			Kind:     "Pod",
			Name:     "api",
			Reason:   "BackOff",
			Message:  "restarting",
		}},
		Dependencies: []diagnostics.DependencyEdge{{
			From:     "deployment/api",
			Relation: "uses",
			To:       "service/db",
		}},
		ServiceViews: []diagnostics.ServiceView{{
			Namespace: "prod",
			Name:      "frontend",
			Chain:     []string{"frontend", "backend", "db"},
			Findings:  []string{"latency spike"},
		}},
		NodePoolViews: []diagnostics.NodePoolView{{
			Name:       "pool-a",
			NodeCount:  3,
			Severities: []string{"critical", "warning"},
			Findings:   []string{"node pressure"},
		}},
		NetworkPaths: []diagnostics.PathResult{{
			Name:     "frontend->backend",
			Steps:    []string{"frontend", "svc/frontend", "svc/backend"},
			Findings: []string{"policy gap"},
		}},
		StoragePaths: []diagnostics.PathResult{{
			Name:     "pvc->pv",
			Steps:    []string{"pvc/data", "pv/data"},
			Findings: []string{"slow disk"},
		}},
		ReleaseReadiness: []diagnostics.Advisory{{
			Title:    "PDB coverage",
			Severity: diagnostics.SeverityWarning,
			Summary:  "missing pdb",
		}},
		UpgradeReadiness: []diagnostics.Advisory{{
			Title:    "Deprecated API",
			Severity: diagnostics.SeverityCritical,
			Summary:  "apps/v1beta1 found",
		}},
		SecurityPosture: []diagnostics.Advisory{{
			Title:    "Webhook TLS",
			Severity: diagnostics.SeverityWarning,
			Summary:  "certificate expires soon",
		}},
		CostWaste: []diagnostics.Advisory{{
			Title:    "Idle node",
			Severity: diagnostics.SeverityInfo,
			Summary:  "low utilization",
		}},
		SLOInsights: []diagnostics.SLOInsight{{
			Namespace:   "prod",
			Service:     "frontend",
			Severity:    diagnostics.SeverityCritical,
			BlastRadius: 90,
			Risk:        "high",
			Summary:     "availability risk",
		}},
		Remediations: []diagnostics.RemediationStep{{
			Title:   "Restart deployment",
			Command: "kubectl rollout restart deploy/frontend -n prod",
		}},
		Comparison: &diagnostics.ClusterComparison{
			BaseContext:    "prod-a",
			CompareContext: "prod-b",
			BaseScore:      72,
			CompareScore:   61,
			NewIssues:      []diagnostics.Issue{{Kind: "Pod", Name: "x", Summary: "new", Severity: diagnostics.SeverityWarning}},
			MissingIssues:  []diagnostics.Issue{{Kind: "Node", Name: "y", Summary: "missing", Severity: diagnostics.SeverityInfo}},
		},
		Options: reportOptions{
			Mode:          "full",
			Output:        "table",
			FailOn:        "warning",
			Profile:       "ci",
			TimelineLimit: 10,
			Focus: diagnostics.FocusSpec{
				Kind:  "namespace",
				Value: "prod",
			},
			AppliedRules: []string{"severity override", "noise suppression"},
		},
	}
}

func TestDefaultChecksAndParseChecks(t *testing.T) {
	checks := defaultChecks()
	for _, expected := range []string{"pods", "rbac", "trends"} {
		if !strings.Contains(checks, expected) {
			t.Fatalf("default checks missing %q in %q", expected, checks)
		}
	}

	parsed := parseChecks(" pods, nodes ,pods,, events ")
	if len(parsed) != 3 {
		t.Fatalf("expected 3 unique checks, got %d", len(parsed))
	}
	for _, key := range []string{"pods", "nodes", "events"} {
		if !parsed[key] {
			t.Fatalf("expected check %q to be enabled", key)
		}
	}
}

func TestApplyProfile(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		initialMode string
		initialFail string
		initialOut  string
		wantChecks  string
		wantMode    string
		wantFail    string
		wantOutput  string
	}{
		{name: "quick", profile: "quick", initialMode: "scan", initialOut: "table", wantChecks: "pods,nodes,events,apiserver", wantMode: "scan", wantOutput: "table"},
		{name: "prod", profile: "prod", initialMode: "scan", initialOut: "table", wantChecks: defaultChecks(), wantMode: "scan", wantFail: "critical", wantOutput: "table"},
		{name: "pre-upgrade", profile: "pre-upgrade", initialMode: "scan", initialOut: "table", wantChecks: defaultChecks(), wantMode: "upgrade-readiness", wantOutput: "table"},
		{name: "network", profile: "network", initialMode: "scan", initialOut: "table", wantChecks: "nodes,dns,ingress,cni,webhooks,events,scheduling", wantMode: "network-path", wantOutput: "table"},
		{name: "incident", profile: "incident", initialMode: "scan", initialOut: "table", wantChecks: "pods,nodes,apiserver,controlplane,dns,cni,ingress,webhooks,storage,events", wantMode: "incident", wantFail: "warning", wantOutput: "table"},
		{name: "release", profile: "release", initialMode: "scan", initialOut: "table", wantChecks: "quotas,pdb,pods,webhooks,ingress,autoscaling,storage,events", wantMode: "release-readiness", wantOutput: "table"},
		{name: "storage", profile: "storage", initialMode: "scan", initialOut: "table", wantChecks: "storage,pods,cni,events", wantMode: "storage-path", wantOutput: "table"},
		{name: "admission", profile: "admission", initialMode: "scan", initialOut: "table", wantChecks: "webhooks,certificates,apiserver,events", wantMode: "security", wantOutput: "table"},
		{name: "cost", profile: "cost", initialMode: "scan", initialOut: "table", wantChecks: "controllers,storage,autoscaling,quotas,ingress", wantMode: "cost", wantOutput: "table"},
		{name: "ci", profile: "ci", initialMode: "scan", initialOut: "table", wantChecks: defaultChecks(), wantMode: "full", wantFail: "warning", wantOutput: "json"},
		{name: "trimmed and existing fail-on", profile: "  prod  ", initialMode: "scan", initialFail: "info", initialOut: "table", wantChecks: defaultChecks(), wantMode: "scan", wantFail: "info", wantOutput: "table"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checks := ""
			output := test.initialOut
			failOn := test.initialFail
			mode := test.initialMode

			applyProfile(&checks, &output, &failOn, &mode, test.profile)

			if checks != test.wantChecks {
				t.Fatalf("checks mismatch: got %q want %q", checks, test.wantChecks)
			}
			if mode != test.wantMode {
				t.Fatalf("mode mismatch: got %q want %q", mode, test.wantMode)
			}
			if failOn != test.wantFail {
				t.Fatalf("fail-on mismatch: got %q want %q", failOn, test.wantFail)
			}
			if output != test.wantOutput {
				t.Fatalf("output mismatch: got %q want %q", output, test.wantOutput)
			}
		})
	}
}

func TestSortIssuesBuildHealthSummaryAndClampScore(t *testing.T) {
	issues := sampleIssues()
	sortIssues(issues)

	if issues[0].Severity != diagnostics.SeverityCritical || issues[0].Name != "node-a" {
		t.Fatalf("expected critical issue first after sorting, got %+v", issues[0])
	}
	if issues[1].Namespace != "ns-a" {
		t.Fatalf("expected namespace sort order to place ns-a before ns-b, got %q", issues[1].Namespace)
	}

	summary := buildHealthSummary(issues)
	if summary.Critical != 1 || summary.Warning != 1 || summary.Info != 1 {
		t.Fatalf("unexpected severity counts: %+v", summary)
	}
	if summary.Score != 70 {
		t.Fatalf("unexpected summary score: %d", summary.Score)
	}
	if len(summary.Categories) == 0 {
		t.Fatal("expected category summaries")
	}
	if clampScore(-10) != 0 || clampScore(120) != 100 || clampScore(42) != 42 {
		t.Fatal("clampScore did not clamp expected values")
	}
}

func TestComposeReportExplainWithBaseline(t *testing.T) {
	previous := scanReport{
		Issues: []diagnostics.Issue{
			{Kind: "Pod", Namespace: "ns-b", Name: "pod-b", Check: "pods", Summary: "pod informational", Severity: diagnostics.SeverityWarning},
			{Kind: "Deployment", Namespace: "old", Name: "gone", Check: "controllers", Summary: "resolved issue", Severity: diagnostics.SeverityInfo},
		},
	}
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	data, err := json.Marshal(previous)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(baselinePath, data, 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	report, err := composeReport(nil, nil, buildHealthSummary(sampleIssues()), sampleIssues(), reportOptions{
		Mode:         "explain",
		Output:       "table",
		BaselinePath: baselinePath,
		Focus: diagnostics.FocusSpec{
			Kind:  "namespace",
			Value: "prod",
		},
	})
	if err != nil {
		t.Fatalf("composeReport returned error: %v", err)
	}
	if report.Baseline == nil {
		t.Fatal("expected baseline diff to be populated")
	}
	if report.Baseline.NewCount != 2 || report.Baseline.ResolvedCount != 1 || report.Baseline.WorsenedCount != 0 {
		t.Fatalf("unexpected baseline diff: %+v", report.Baseline)
	}
	if len(report.Explanations) == 0 {
		t.Fatal("expected explanations for explain mode")
	}
}

func TestComposeReportModeSpecificSections(t *testing.T) {
	issues := sampleIssues()
	summary := buildHealthSummary(issues)

	tests := []struct {
		name  string
		opts  reportOptions
		check func(t *testing.T, report scanReport)
	}{
		{
			name: "release-readiness",
			opts: reportOptions{Mode: "release-readiness", Output: "table"},
			check: func(t *testing.T, report scanReport) {
				t.Helper()
				if report.GeneratedAt.IsZero() {
					t.Fatal("expected generated timestamp to be set")
				}
			},
		},
		{
			name: "remediation",
			opts: reportOptions{Mode: "remediation", Output: "table"},
			check: func(t *testing.T, report scanReport) {
				t.Helper()
				if len(report.Remediations) == 0 {
					t.Fatal("expected remediation steps")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := composeReport(nil, nil, summary, issues, test.opts)
			if err != nil {
				t.Fatalf("composeReport returned error: %v", err)
			}
			test.check(t, report)
		})
	}
}

func TestRenderModeAndRenderHelpers(t *testing.T) {
	report := sampleReport()

	fullOutput := captureStdout(t, func() {
		renderMode(report)
	})
	for _, expected := range []string{
		"Health score:",
		"Diff:",
		"Timeline:",
		"Dependencies:",
		"Service Views:",
		"Node Pool Views:",
		"Network Paths:",
		"Storage Paths:",
		"Release Readiness:",
		"Upgrade Readiness:",
		"Security Posture:",
		"Cost Waste:",
		"SLO Insights:",
		"Cluster Comparison:",
		"Remediation:",
		"SEVERITY  OBJECT",
	} {
		if !strings.Contains(fullOutput, expected) {
			t.Fatalf("expected full render output to contain %q\n%s", expected, fullOutput)
		}
	}

	emptyOutput := captureStdout(t, func() {
		minimal := scanReport{Summary: healthSummary{Score: 100, Categories: []categorySummary{}}, Options: reportOptions{Mode: "scan"}}
		minimal.Issues = nil
		renderMode(minimal)
	})
	if !strings.Contains(emptyOutput, "No obvious issues detected") {
		t.Fatalf("expected healthy message for empty scan output, got %q", emptyOutput)
	}

	diffOutput := captureStdout(t, func() {
		renderDiff(nil)
	})
	if !strings.Contains(diffOutput, "no baseline provided") {
		t.Fatalf("expected nil baseline message, got %q", diffOutput)
	}
}

func TestRenderModeSwitchCases(t *testing.T) {
	base := sampleReport()
	tests := []struct {
		mode     string
		expected string
	}{
		{mode: "explain", expected: "Explanations:"},
		{mode: "incident", expected: "SEVERITY  OBJECT"},
		{mode: "diff", expected: "Diff:"},
		{mode: "timeline", expected: "Timeline:"},
		{mode: "dependencies", expected: "Dependencies:"},
		{mode: "service-view", expected: "Service Views:"},
		{mode: "node-pool-view", expected: "Node Pool Views:"},
		{mode: "network-path", expected: "Network Paths:"},
		{mode: "storage-path", expected: "Storage Paths:"},
		{mode: "release-readiness", expected: "Release Readiness:"},
		{mode: "upgrade-readiness", expected: "Upgrade Readiness:"},
		{mode: "security", expected: "Security Posture:"},
		{mode: "cost", expected: "Cost Waste:"},
		{mode: "slo", expected: "SLO Insights:"},
		{mode: "remediation", expected: "Remediation:"},
		{mode: "multi-cluster-compare", expected: "Cluster Comparison:"},
	}

	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			report := base
			report.Options.Mode = test.mode
			output := captureStdout(t, func() {
				renderMode(report)
			})
			if !strings.Contains(output, test.expected) {
				t.Fatalf("expected %q output to contain %q\n%s", test.mode, test.expected, output)
			}
		})
	}
}

func TestRenderMarkdownAndHTMLReport(t *testing.T) {
	report := sampleReport()

	markdown := renderMarkdownReport(report)
	for _, expected := range []string{
		"# kdoctor report",
		"Generated: 2026-04-07T12:00:00Z",
		"Focus: namespace=prod",
		"## Explain",
		"## Diff",
		"## Timeline",
		"## Dependencies",
		"## Service Views",
		"## Node Pool Views",
		"## Network Paths",
		"## Storage Paths",
		"## Release Readiness",
		"## Upgrade Readiness",
		"## Security Posture",
		"## Cost Waste",
		"## SLO Insights",
		"## Cluster Comparison",
		"## Remediation",
		"## Issues",
	} {
		if !strings.Contains(markdown, expected) {
			t.Fatalf("expected markdown report to contain %q", expected)
		}
	}

	htmlReport := renderHTMLReport(report)
	for _, expected := range []string{"<!doctype html>", "<pre>", "# kdoctor report"} {
		if !strings.Contains(htmlReport, expected) {
			t.Fatalf("expected html report to contain %q", expected)
		}
	}
}

func TestWriteBaselineAndRenderedReport(t *testing.T) {
	report := sampleReport()
	dir := t.TempDir()

	baselinePath := filepath.Join(dir, "baseline.json")
	if err := writeBaseline(baselinePath, report); err != nil {
		t.Fatalf("writeBaseline returned error: %v", err)
	}
	baselineBytes, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline file: %v", err)
	}
	if !strings.Contains(string(baselineBytes), "generatedAt") {
		t.Fatalf("expected serialized report in baseline file, got %q", string(baselineBytes))
	}

	markdownPath := filepath.Join(dir, "report.md")
	if err := writeRenderedReport(markdownPath, "markdown", report); err != nil {
		t.Fatalf("writeRenderedReport markdown returned error: %v", err)
	}
	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read markdown report: %v", err)
	}
	if !strings.Contains(string(markdownBytes), "## Issues") {
		t.Fatalf("expected markdown report content, got %q", string(markdownBytes))
	}

	htmlPath := filepath.Join(dir, "report.html")
	if err := writeRenderedReport(htmlPath, "html", report); err != nil {
		t.Fatalf("writeRenderedReport html returned error: %v", err)
	}
	htmlBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read html report: %v", err)
	}
	if !strings.Contains(string(htmlBytes), "<!doctype html>") {
		t.Fatalf("expected html report content, got %q", string(htmlBytes))
	}
}

func TestLoadAndCompareBaseline(t *testing.T) {
	previous := scanReport{
		Issues: []diagnostics.Issue{
			{Kind: "Pod", Namespace: "team-a", Name: "api", Check: "pods", Summary: "same issue", Severity: diagnostics.SeverityInfo},
			{Kind: "Deployment", Namespace: "team-a", Name: "worker", Check: "controllers", Summary: "resolved issue", Severity: diagnostics.SeverityWarning},
		},
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	data, err := json.Marshal(previous)
	if err != nil {
		t.Fatalf("marshal previous report: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write previous report: %v", err)
	}

	current := []diagnostics.Issue{
		{Kind: "Pod", Namespace: "team-a", Name: "api", Check: "pods", Summary: "same issue", Severity: diagnostics.SeverityWarning},
		{Kind: "Node", Name: "node-a", Check: "nodes", Summary: "new issue", Severity: diagnostics.SeverityCritical},
	}

	diff, err := loadAndCompareBaseline(path, current)
	if err != nil {
		t.Fatalf("loadAndCompareBaseline returned error: %v", err)
	}
	if diff.NewCount != 1 || diff.ResolvedCount != 1 || diff.WorsenedCount != 1 {
		t.Fatalf("unexpected diff counts: %+v", diff)
	}
	if len(diff.NewIssues) != 1 || len(diff.Resolved) != 1 || len(diff.Worsened) != 1 {
		t.Fatalf("unexpected diff issue lists: %+v", diff)
	}
}

func TestMeetsFailThresholdAndSeverityWeight(t *testing.T) {
	issues := sampleIssues()
	if meetsFailThreshold(issues, "") {
		t.Fatal("expected empty threshold to return false")
	}
	if !meetsFailThreshold(issues, "warning") {
		t.Fatal("expected warning threshold to match")
	}
	if meetsFailThreshold([]diagnostics.Issue{{Severity: diagnostics.SeverityInfo}}, "critical") {
		t.Fatal("expected critical threshold to ignore info-only issues")
	}
	if severityWeight(diagnostics.SeverityCritical) != 3 || severityWeight(diagnostics.SeverityWarning) != 2 || severityWeight(diagnostics.SeverityInfo) != 1 {
		t.Fatal("unexpected severity weights")
	}
}

func TestBuildComparisonReportReturnsErrorForInvalidKubeconfig(t *testing.T) {
	comparison, err := buildComparisonReport(compareInput{
		BaseKubeconfig: "/definitely/missing/kubeconfig",
		CompareContext: "staging",
		Namespace:      "prod",
		Checks:         "pods,nodes",
		Timeout:        time.Second,
	})
	if err == nil {
		t.Fatalf("expected error for invalid kubeconfig, got comparison %+v", comparison)
	}
}

func TestMainExitsForInvalidKubeconfig(t *testing.T) {
	if os.Getenv("KDOC_MAIN_SUBPROCESS") == "1" {
		oldArgs := os.Args
		oldCommandLine := flag.CommandLine
		defer func() {
			os.Args = oldArgs
			flag.CommandLine = oldCommandLine
		}()

		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{
			"kdoctor",
			"-kubeconfig", "/definitely/missing/kubeconfig",
			"-profile", "quick",
			"-focus-kind", "namespace",
			"-focus", "prod",
		}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainExitsForInvalidKubeconfig")
	cmd.Env = append(os.Environ(), "KDOC_MAIN_SUBPROCESS=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestFatalfExitsWithStatusOne(t *testing.T) {
	if os.Getenv("KDOC_FATALF_SUBPROCESS") == "1" {
		fatalf("boom %s", "now")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFatalfExitsWithStatusOne")
	cmd.Env = append(os.Environ(), "KDOC_FATALF_SUBPROCESS=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestMeetsFailThresholdInvalidValueExits(t *testing.T) {
	if os.Getenv("KDOC_FAILON_SUBPROCESS") == "1" {
		_ = meetsFailThreshold(nil, "broken")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMeetsFailThresholdInvalidValueExits")
	cmd.Env = append(os.Environ(), "KDOC_FAILON_SUBPROCESS=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}
