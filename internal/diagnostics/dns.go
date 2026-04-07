package diagnostics

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckDNS(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	var issues []Issue

	deployments, err := cs.AppsV1().Deployments(metav1.NamespaceSystem).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	foundDNS := false
	for _, deploy := range deployments.Items {
		name := strings.ToLower(deploy.Name)
		if !strings.Contains(name, "coredns") && !strings.Contains(name, "dns") {
			continue
		}
		foundDNS = true
		desired := int32(1)
		if deploy.Spec.Replicas != nil {
			desired = *deploy.Spec.Replicas
		}
		if deploy.Status.AvailableReplicas < desired {
			issues = append(issues, Issue{
				Kind:           "DNS",
				Namespace:      deploy.Namespace,
				Name:           deploy.Name,
				Severity:       SeverityCritical,
				Category:       "networking",
				Check:          "dns",
				Summary:        fmt.Sprintf("DNS deployment not fully available (%d/%d)", deploy.Status.AvailableReplicas, desired),
				Recommendation: "Check CoreDNS rollout, kube-system pod logs, and node scheduling conditions.",
			})
		}
	}

	if !foundDNS {
		issues = append(issues, Issue{
			Kind:           "DNS",
			Namespace:      metav1.NamespaceSystem,
			Severity:       SeverityCritical,
			Category:       "networking",
			Check:          "dns",
			Summary:        "no DNS deployment detected in kube-system",
			Recommendation: "Ensure CoreDNS or an equivalent cluster DNS service is installed and running.",
		})
		return issues, nil
	}

	svc, err := cs.CoreV1().Services(metav1.NamespaceSystem).Get(ctx, "kube-dns", metav1.GetOptions{})
	if err == nil {
		eps, epsErr := cs.CoreV1().Endpoints(metav1.NamespaceSystem).Get(ctx, svc.Name, metav1.GetOptions{})
		if epsErr == nil && !hasReadyAddress(eps) {
			issues = append(issues, Issue{
				Kind:           "DNS",
				Namespace:      svc.Namespace,
				Name:           svc.Name,
				Severity:       SeverityCritical,
				Category:       "networking",
				Check:          "dns-endpoints",
				Summary:        "kube-dns service has no ready endpoints",
				Recommendation: "Check CoreDNS pod readiness, service selectors, and kube-proxy/CNI health.",
			})
		}

		start := time.Now()
		res := cs.CoreV1().RESTClient().Get().Namespace(svc.Namespace).Resource("services").Name(svc.Name).SubResource("proxy").Do(ctx)
		_, probeErr := res.Raw()
		latency := time.Since(start)
		if probeErr != nil {
			issues = append(issues, Issue{
				Kind:           "DNS",
				Namespace:      svc.Namespace,
				Name:           svc.Name,
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "dns-probe",
				Summary:        fmt.Sprintf("DNS service proxy probe failed: %v", probeErr),
				Recommendation: "Verify kube-dns service, CoreDNS pod ports, and API proxy reachability.",
			})
		} else if latency > 1500*time.Millisecond {
			issues = append(issues, Issue{
				Kind:           "DNS",
				Namespace:      svc.Namespace,
				Name:           svc.Name,
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "dns-latency",
				Summary:        fmt.Sprintf("DNS service proxy is slow (~%dms)", latency.Milliseconds()),
				Recommendation: "Inspect CoreDNS load, upstream DNS latency, and cluster networking.",
			})
		}
	}

	return issues, nil
}
