package diagnostics

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var knownCNIDaemonSets = []string{
	"calico-node", "canal", "flannel", "kube-flannel-ds", "weave-net", "cilium", "aws-node", "antrea-agent", "kube-router",
}

// CheckCNIAndCSI highlights networking/storage agent readiness issues.
func CheckCNIAndCSI(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	var issues []Issue

	ds, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err == nil {
		foundCNI := false
		for _, d := range ds.Items {
			nameLower := strings.ToLower(d.Name)
			if isKnownCNI(nameLower) {
				foundCNI = true
				if d.Status.NumberAvailable < d.Status.DesiredNumberScheduled {
					issues = append(issues, Issue{
						Kind:           "CNI",
						Namespace:      d.Namespace,
						Name:           d.Name,
						Severity:       SeverityCritical,
						Category:       "networking",
						Check:          "cni",
						Summary:        fmt.Sprintf("CNI daemonset not healthy (%d/%d ready)", d.Status.NumberAvailable, d.Status.DesiredNumberScheduled),
						Recommendation: "Check CNI pods in kube-system, image pull status, node taints/affinity, and host networking permissions.",
					})
				}
			}
			if strings.Contains(nameLower, "csi") {
				if d.Status.NumberAvailable < d.Status.DesiredNumberScheduled {
					issues = append(issues, Issue{
						Kind:           "CSI",
						Namespace:      d.Namespace,
						Name:           d.Name,
						Severity:       SeverityWarning,
						Category:       "storage",
						Check:          "csi",
						Summary:        fmt.Sprintf("CSI daemonset not healthy (%d/%d ready)", d.Status.NumberAvailable, d.Status.DesiredNumberScheduled),
						Recommendation: "Inspect CSI node pods; verify hostPath mounts, permissions, and node selectors.",
					})
				}
			}
		}
		if !foundCNI {
			issues = append(issues, Issue{
				Kind:           "CNI",
				Namespace:      metav1.NamespaceSystem,
				Name:           "",
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "cni",
				Summary:        "no known CNI daemonset detected",
				Recommendation: "Ensure a CNI plugin is installed (Calico, Cilium, Flannel, etc.) and running in kube-system.",
			})
		}
	}

	csidrivers, err := cs.StorageV1().CSIDrivers().List(ctx, metav1.ListOptions{})
	if err == nil {
		if len(csidrivers.Items) == 0 {
			issues = append(issues, Issue{
				Kind:           "CSI",
				Severity:       SeverityInfo,
				Category:       "storage",
				Check:          "csi-driver",
				Summary:        "no CSI drivers registered",
				Recommendation: "Install a CSI driver for your storage backend or verify API access to CSIDriver objects.",
			})
		}
	}

	return issues, nil
}

func isKnownCNI(name string) bool {
	for _, n := range knownCNIDaemonSets {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}
