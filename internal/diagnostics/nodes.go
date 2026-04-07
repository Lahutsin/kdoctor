package diagnostics

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type kubeletConfigzResponse struct {
	KubeletConfig kubeletConfigSnapshot `json:"kubeletconfig"`
}

type kubeletConfigSnapshot struct {
	Authentication struct {
		Anonymous struct {
			Enabled *bool `json:"enabled"`
		} `json:"anonymous"`
		Webhook struct {
			Enabled *bool `json:"enabled"`
		} `json:"webhook"`
	} `json:"authentication"`
	Authorization struct {
		Mode string `json:"mode"`
	} `json:"authorization"`
	ReadOnlyPort       *int32   `json:"readOnlyPort"`
	ServerTLSBootstrap *bool    `json:"serverTLSBootstrap"`
	RotateCertificates *bool    `json:"rotateCertificates"`
	TLSMinVersion      string   `json:"tlsMinVersion"`
	TLSCipherSuites    []string `json:"tlsCipherSuites"`
}

type nodeExposure struct {
	probeAddress string
	externalIP   string
	openPorts    []int
}

// CheckNodes highlights nodes that are NotReady or under pressure conditions.
func CheckNodes(ctx context.Context, cs *kubernetes.Clientset) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}

	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	podsByNode := groupPodsByNode(pods.Items)

	for _, node := range nodes.Items {
		readyCond := nodeReadyCondition(node.Status.Conditions)
		if readyCond == nil || readyCond.Status != v1.ConditionTrue {
			summary := "node is NotReady"
			if readyCond != nil && readyCond.Reason != "" {
				summary = fmt.Sprintf("node is NotReady: %s", readyCond.Reason)
				if readyCond.Message != "" {
					summary = fmt.Sprintf("%s (%s)", summary, readyCond.Message)
				}
			}
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityCritical,
				Category:       "networking",
				Check:          "nodes-ready",
				Summary:        summary,
				Recommendation: "Check kubelet status, node reachability, and control-plane logs; run kubectl describe node for condition details.",
			})
		}

		if node.Spec.Unschedulable {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           node.Name,
				Severity:       SeverityWarning,
				Category:       "networking",
				Check:          "node-cordoned",
				Summary:        "node is cordoned (unschedulable)",
				Recommendation: "Uncordon the node if maintenance is complete, or expect reduced scheduling capacity.",
			})
		}

		issues = append(issues, kubeletSecurityConfigIssues(ctx, cs, node)...)
		exposure := probeNodeExposure(node)
		issues = append(issues, nodePublicExposureIssues(node, exposure)...)
		issues = append(issues, staleNodeIssues(node, readyCond)...)
		issues = append(issues, suspiciousNodeSchedulingMetadataIssues(node)...)
		issues = append(issues, sensitiveNodeMountIssues(node, podsByNode[node.Name])...)
		issues = append(issues, unschedulableReachableNodeIssues(node, readyCond, exposure)...)

		for _, cond := range node.Status.Conditions {
			if cond.Status != v1.ConditionTrue {
				continue
			}
			switch cond.Type {
			case v1.NodeMemoryPressure:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Category:       "networking",
					Check:          "node-memory-pressure",
					Summary:        "node reports memory pressure",
					Recommendation: "Evict or reschedule pods, increase node memory, or tune resource requests/limits.",
				})
			case v1.NodeDiskPressure:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Category:       "networking",
					Check:          "node-disk-pressure",
					Summary:        "node reports disk pressure",
					Recommendation: "Free disk space, rotate logs, or expand the node volume.",
				})
			case v1.NodeNetworkUnavailable:
				issues = append(issues, Issue{
					Kind:           "Node",
					Name:           node.Name,
					Severity:       SeverityWarning,
					Category:       "networking",
					Check:          "node-network-unavailable",
					Summary:        "node network is unavailable",
					Recommendation: "Verify CNI plugin, node routes, and cloud provider networking.",
				})
			}
		}
	}

	issues = append(issues, kubeletCertificateIssues(ctx, cs)...)

	return dedupeIssues(issues), nil
}

func nodeReadyCondition(conditions []v1.NodeCondition) *v1.NodeCondition {
	for i := range conditions {
		if conditions[i].Type == v1.NodeReady {
			return &conditions[i]
		}
	}
	return nil
}

func kubeletSecurityConfigIssues(ctx context.Context, cs *kubernetes.Clientset, node v1.Node) []Issue {
	config, ok := fetchKubeletConfig(ctx, cs, node.Name)
	if !ok {
		return nil
	}
	issues := make([]Issue, 0)
	if config.Authentication.Anonymous.Enabled != nil && *config.Authentication.Anonymous.Enabled {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "kubelet-anonymous-auth",
			Summary:        "kubelet anonymous authentication appears enabled",
			Recommendation: "Set kubelet authentication.anonymous.enabled=false and rely on client certificates or bearer auth only.",
		})
	}
	if config.Authentication.Webhook.Enabled != nil && !*config.Authentication.Webhook.Enabled {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "kubelet-webhook-authn-disabled",
			Summary:        "kubelet webhook authentication appears disabled",
			Recommendation: "Enable kubelet authentication.webhook so bearer tokens are verified centrally by the API server.",
		})
	}
	if mode := strings.ToUpper(strings.TrimSpace(config.Authorization.Mode)); mode != "" && mode != "WEBHOOK" {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "kubelet-webhook-authz-disabled",
			Summary:        fmt.Sprintf("kubelet authorization mode is %s instead of Webhook", config.Authorization.Mode),
			Recommendation: "Set kubelet authorization.mode=Webhook so node API access is authorized through the control plane.",
		})
	}
	if config.ReadOnlyPort != nil && *config.ReadOnlyPort > 0 {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "kubelet-readonly-port",
			Summary:        fmt.Sprintf("kubelet read-only port is enabled on %d", *config.ReadOnlyPort),
			Recommendation: "Disable kubelet readOnlyPort so metrics and pod information are not exposed without authentication.",
		})
	}
	return issues
}

func fetchKubeletConfig(ctx context.Context, cs *kubernetes.Clientset, nodeName string) (kubeletConfigSnapshot, bool) {
	raw, err := cs.CoreV1().RESTClient().Get().AbsPath("/api/v1/nodes/" + nodeName + "/proxy/configz").Do(ctx).Raw()
	if err != nil || len(raw) == 0 {
		return kubeletConfigSnapshot{}, false
	}
	var response kubeletConfigzResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return kubeletConfigSnapshot{}, false
	}
	return response.KubeletConfig, true
}

func kubeletCertificateIssues(ctx context.Context, cs *kubernetes.Clientset) []Issue {
	csrs, err := cs.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	latest := map[string]csrCertificateView{}
	for _, csr := range csrs.Items {
		if len(csr.Status.Certificate) == 0 {
			continue
		}
		signer := strings.ToLower(csr.Spec.SignerName)
		if !strings.Contains(signer, "kubelet") {
			continue
		}
		nodeName := nodeNameFromCSR(csr)
		if nodeName == "" {
			continue
		}
		for _, cert := range parsePEMCertificates(csr.Status.Certificate) {
			if cert == nil {
				continue
			}
			key := nodeName + "|" + signer
			current, found := latest[key]
			if !found || cert.NotAfter.After(current.cert.NotAfter) {
				latest[key] = csrCertificateView{nodeName: nodeName, signer: signer, cert: cert}
			}
		}
	}
	issues := make([]Issue, 0, len(latest))
	for _, view := range latest {
		if time.Until(view.cert.NotAfter) <= 0 {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           view.nodeName,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "kubelet-cert-expired",
				Summary:        fmt.Sprintf("kubelet certificate from signer %s is expired (CN=%s, notAfter=%s)", view.signer, view.cert.Subject.CommonName, view.cert.NotAfter.Format(time.RFC3339)),
				Recommendation: "Restore kubelet certificate rotation or serving certificate issuance so nodes do not keep expired kubelet credentials.",
			})
		}
		if finding := weakCertificateFinding(view.cert); finding != "" {
			issues = append(issues, Issue{
				Kind:           "Node",
				Name:           view.nodeName,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "kubelet-cert-weak",
				Summary:        finding,
				Recommendation: "Reissue kubelet certificates with strong key sizes and modern signature algorithms.",
			})
		}
	}
	return issues
}

type csrCertificateView struct {
	nodeName string
	signer   string
	cert     *x509.Certificate
}

func nodeNameFromCSR(csr certificatesv1.CertificateSigningRequest) string {
	commonName := ""
	for _, cert := range parsePEMCertificates(csr.Status.Certificate) {
		if cert != nil && cert.Subject.CommonName != "" {
			commonName = cert.Subject.CommonName
			break
		}
	}
	return nodeNameFromCSRSpec(csr.Name, csr.Spec.Username, commonName)
}

func nodeNameFromCSRSpec(csrName, username, commonName string) string {
	for _, candidate := range []string{username, commonName, csrName} {
		candidate = strings.TrimSpace(candidate)
		if strings.HasPrefix(candidate, "system:node:") {
			return strings.TrimPrefix(candidate, "system:node:")
		}
	}
	return ""
}

func probeNodeExposure(node v1.Node) nodeExposure {
	externalIP := nodeAddress(node, v1.NodeExternalIP)
	probeAddress := externalIP
	if probeAddress == "" {
		probeAddress = nodeAddress(node, v1.NodeInternalIP)
	}
	exposure := nodeExposure{probeAddress: probeAddress, externalIP: externalIP}
	if probeAddress == "" {
		return exposure
	}
	ports := []int{22, 2222, 10250, 10255}
	for _, port := range ports {
		if tcpPortReachable(probeAddress, port, 400*time.Millisecond) {
			exposure.openPorts = append(exposure.openPorts, port)
		}
	}
	sort.Ints(exposure.openPorts)
	return exposure
}

func nodePublicExposureIssues(node v1.Node, exposure nodeExposure) []Issue {
	issues := make([]Issue, 0)
	if exposure.externalIP != "" && len(exposure.openPorts) > 0 {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "node-public-management-exposure",
			Summary:        fmt.Sprintf("node has a public IP and management ports reachable from the diagnostic host: %s", formatPorts(exposure.openPorts)),
			Recommendation: "Restrict worker and control-plane nodes with security groups/firewalls so SSH and kubelet ports are not reachable from broad networks.",
			References:     []string{"publicIP=" + exposure.externalIP},
		})
	}
	if hasAnyPort(exposure.openPorts, 22, 2222) {
		severity := SeverityWarning
		if exposure.externalIP != "" || nodeLooksControlPlane(node) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "node-ssh-exposure",
			Summary:        fmt.Sprintf("SSH is reachable on node address %s (%s)", exposure.probeAddress, formatPorts(filterPorts(exposure.openPorts, 22, 2222))),
			Recommendation: "Disable broad SSH access to nodes, prefer just-in-time access paths, and keep control-plane or sensitive workers off directly reachable SSH endpoints.",
		})
	}
	return issues
}

func staleNodeIssues(node v1.Node, readyCond *v1.NodeCondition) []Issue {
	if readyCond == nil || readyCond.Status == v1.ConditionTrue || node.DeletionTimestamp != nil {
		return nil
	}
	lastSeen := readyCond.LastHeartbeatTime.Time
	if lastSeen.IsZero() {
		lastSeen = readyCond.LastTransitionTime.Time
	}
	if lastSeen.IsZero() || time.Since(lastSeen) < 7*24*time.Hour {
		return nil
	}
	return []Issue{{
		Kind:           "Node",
		Name:           node.Name,
		Severity:       SeverityCritical,
		Category:       "security",
		Check:          "node-stale-membership",
		Summary:        fmt.Sprintf("node appears stale and still joined to the cluster; last heartbeat was %s ago", humanDuration(time.Since(lastSeen))),
		Recommendation: "Drain and remove long-dead nodes from the cluster so stale kubelet identities, labels, and addresses cannot linger in scheduling and trust decisions.",
	}}
}

func suspiciousNodeSchedulingMetadataIssues(node v1.Node) []Issue {
	issues := make([]Issue, 0)
	if findings := suspiciousNodeLabels(node.Labels); len(findings) > 0 {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "node-suspicious-labels",
			Summary:        fmt.Sprintf("node has custom scheduling labels that can pin workloads: %s", strings.Join(findings, ", ")),
			Recommendation: "Protect sensitive node-placement labels with trusted prefixes or NodeRestriction-safe conventions so compromised kubelets cannot steer workloads.",
		})
	}
	if findings := suspiciousNodeTaints(node.Spec.Taints); len(findings) > 0 {
		issues = append(issues, Issue{
			Kind:           "Node",
			Name:           node.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "node-suspicious-taints",
			Summary:        fmt.Sprintf("node has custom taints that can influence workload pinning: %s", strings.Join(findings, ", ")),
			Recommendation: "Review non-standard taints on nodes and ensure only trusted automation can assign placement-related taints and labels.",
		})
	}
	return issues
}

func sensitiveNodeMountIssues(node v1.Node, pods []v1.Pod) []Issue {
	findings := make([]string, 0)
	severity := SeverityWarning
	for _, pod := range pods {
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath == nil || volume.HostPath.Path == "" {
				continue
			}
			if !sensitiveNodeHostPath(volume.HostPath.Path) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, volume.HostPath.Path))
			if isCriticalNodeHostPath(volume.HostPath.Path) {
				severity = SeverityCritical
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	items := uniqueStrings(findings)
	sort.Strings(items)
	refs := items
	if len(refs) > 5 {
		refs = refs[:5]
	}
	return []Issue{{
		Kind:           "Node",
		Name:           node.Name,
		Severity:       severity,
		Category:       "security",
		Check:          "node-sensitive-hostpath",
		Summary:        fmt.Sprintf("pods on this node mount host paths that expose kubelet state or host credentials (%d mounts)", len(items)),
		Recommendation: "Remove hostPath mounts to kubelet state, SSH material, and Kubernetes host credentials unless the workload is explicitly trusted and tightly isolated.",
		References:     refs,
	}}
}

func unschedulableReachableNodeIssues(node v1.Node, readyCond *v1.NodeCondition, exposure nodeExposure) []Issue {
	if !node.Spec.Unschedulable || readyCond == nil || readyCond.Status != v1.ConditionTrue {
		return nil
	}
	if len(exposure.openPorts) == 0 && exposure.externalIP == "" {
		return nil
	}
	severity := SeverityWarning
	if hasAnyPort(exposure.openPorts, 22, 2222, 10250, 10255) {
		severity = SeverityCritical
	}
	return []Issue{{
		Kind:           "Node",
		Name:           node.Name,
		Severity:       severity,
		Category:       "security",
		Check:          "node-unschedulable-reachable",
		Summary:        fmt.Sprintf("unschedulable node remains reachable over management paths (%s)", formatPorts(exposure.openPorts)),
		Recommendation: "If the node is quarantined or suspected compromised, isolate it at the network layer and revoke kubelet/node access instead of only cordoning it.",
	}}
}

func groupPodsByNode(pods []v1.Pod) map[string][]v1.Pod {
	result := make(map[string][]v1.Pod)
	for _, pod := range pods {
		if pod.Spec.NodeName == "" {
			continue
		}
		result[pod.Spec.NodeName] = append(result[pod.Spec.NodeName], pod)
	}
	return result
}

func nodeAddress(node v1.Node, addrType v1.NodeAddressType) string {
	for _, address := range node.Status.Addresses {
		if address.Type == addrType && strings.TrimSpace(address.Address) != "" {
			return address.Address
		}
	}
	return ""
}

func tcpPortReachable(address string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return "no open management ports observed"
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("tcp/%d", port))
	}
	return strings.Join(values, ", ")
}

func hasAnyPort(found []int, expected ...int) bool {
	for _, port := range found {
		for _, candidate := range expected {
			if port == candidate {
				return true
			}
		}
	}
	return false
}

func filterPorts(found []int, expected ...int) []int {
	values := make([]int, 0)
	for _, port := range found {
		for _, candidate := range expected {
			if port == candidate {
				values = append(values, port)
				break
			}
		}
	}
	return values
}

func nodeLooksControlPlane(node v1.Node) bool {
	for key := range node.Labels {
		if strings.HasPrefix(key, "node-role.kubernetes.io/control-plane") || strings.HasPrefix(key, "node-role.kubernetes.io/master") {
			return true
		}
	}
	return false
}

func suspiciousNodeLabels(labels map[string]string) []string {
	findings := make([]string, 0)
	for key, value := range labels {
		if !looksPlacementSensitive(key, value) {
			continue
		}
		if trustedNodeMetadataPrefix(key) {
			continue
		}
		findings = append(findings, key+"="+value)
	}
	return uniqueStrings(findings)
}

func suspiciousNodeTaints(taints []v1.Taint) []string {
	findings := make([]string, 0)
	for _, taint := range taints {
		if !looksPlacementSensitive(taint.Key, taint.Value) {
			continue
		}
		if trustedNodeMetadataPrefix(taint.Key) {
			continue
		}
		findings = append(findings, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
	}
	return uniqueStrings(findings)
}

func looksPlacementSensitive(key, value string) bool {
	text := strings.ToLower(key + "=" + value)
	for _, marker := range []string{"dedicated", "tenant", "team", "workload", "pci", "secure", "isolated", "restricted", "compliance", "prod", "production", "payment", "secret", "identity"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func trustedNodeMetadataPrefix(key string) bool {
	for _, prefix := range []string{
		"kubernetes.io/",
		"node.kubernetes.io/",
		"node-role.kubernetes.io/",
		"topology.kubernetes.io/",
		"failure-domain.beta.kubernetes.io/",
		"beta.kubernetes.io/",
		"node-restriction.kubernetes.io/",
		"eks.amazonaws.com/",
		"alpha.eksctl.io/",
		"cloud.google.com/",
		"cloud.google.kubernetes.io/",
		"kubernetes.azure.com/",
		"agentpool",
		"karpenter.sh/",
		"karpenter.k8s.aws/",
		"cluster.x-k8s.io/",
		"kops.k8s.io/",
		"cilium.io/",
	} {
		if strings.HasPrefix(key, prefix) || key == prefix {
			return true
		}
	}
	return false
}

func sensitiveNodeHostPath(path string) bool {
	path = strings.ToLower(path)
	for _, marker := range []string{"/var/lib/kubelet", "/etc/kubernetes", "/var/lib/etcd", "/root/.ssh", "/.ssh", "/etc/ssh", "/var/lib/cloud", "/var/lib/kubelet/pki", "/var/lib/kubelet/config.yaml"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func isCriticalNodeHostPath(path string) bool {
	path = strings.ToLower(path)
	for _, marker := range []string{"/var/lib/kubelet", "/etc/kubernetes", "/var/lib/etcd", "/root/.ssh", "/.ssh"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}
