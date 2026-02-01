package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"kdoctor/internal/diagnostics"
)

func main() {
	var kubeconfig string
	var namespace string
	var kubeContext string
	var checks string
	var timeoutSec int

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config)")
	flag.StringVar(&namespace, "namespace", "", "Namespace to inspect (empty for all)")
	flag.StringVar(&kubeContext, "context", "", "Kubeconfig context to use")
	flag.StringVar(&checks, "checks", "pods,nodes,events,controllers,apiserver,webhooks,cni,controlplane", "Comma-separated checks to run")
	flag.IntVar(&timeoutSec, "timeout", 30, "Overall timeout in seconds for all checks")
	flag.Parse()

	if kubeconfig == "" {
		kubeconfig = diagnostics.DefaultKubeconfig()
	}

	enabled := parseChecks(checks)
	checker, err := diagnostics.NewChecker(kubeconfig, kubeContext, namespace, enabled, time.Duration(timeoutSec)*time.Second)
	if err != nil {
		fatalf("init client: %v", err)
	}

	issues, err := checker.Run(context.Background())
	if err != nil {
		fatalf("run checks: %v", err)
	}

	if len(issues) == 0 {
		fmt.Println("No obvious issues detected. Cluster looks healthy from the inspected signals.")
		return
	}

	sortIssues(issues)
	renderTable(issues)
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
