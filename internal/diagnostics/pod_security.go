package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type securityContainerView struct {
	kind            string
	name            string
	image           string
	securityContext *corev1.SecurityContext
	volumeMounts    []corev1.VolumeMount
}

func CheckPodSecurity(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	namespaceMetaMap, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	issues := make([]Issue, 0)
	issues = append(issues, evaluatePSANamespaceLabels(namespaceMetaMap)...)
	issues = append(issues, evaluatePSAPolicyDrift(namespaceMetaMap)...)

	for _, pod := range pods.Items {
		if isWindowsPod(pod) {
			continue
		}
		nsMeta := namespaceMetaMap[pod.Namespace]
		issues = append(issues, evaluatePodLevelSecurity(pod, nsMeta)...)
		issues = append(issues, evaluateContainerSecurity(pod, nsMeta)...)
		issues = append(issues, evaluatePSARestrictedViolations(pod, nsMeta)...)
	}

	return dedupeIssues(issues), nil
}

func evaluatePSANamespaceLabels(namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, ns := range sortedNamespaceMeta(namespaces) {
		enforce := psaLevel(ns.labels, "enforce")
		if enforce == "" && !looksLikeSystemNamespace(ns.name) {
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "psa-enforce-missing",
				Summary:        "namespace does not define pod-security.kubernetes.io/enforce",
				Recommendation: "Set Pod Security Admission labels explicitly, ideally enforce=restricted for regular application namespaces.",
			})
			continue
		}
		if enforce != "" && !isValidPSALevel(enforce) {
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "psa-enforce-invalid",
				Summary:        fmt.Sprintf("namespace uses invalid PSA enforce level %q", enforce),
				Recommendation: "Use one of the supported Pod Security Admission levels: restricted, baseline, or privileged.",
			})
		}
		if looksLikeSystemNamespace(ns.name) {
			if enforce == "" || enforce == "restricted" {
				continue
			}
			if justificationForNamespace(ns) == "" {
				issues = append(issues, Issue{
					Kind:           "Namespace",
					Name:           ns.name,
					Severity:       SeverityInfo,
					Category:       "security",
					Check:          "psa-system-namespace-exception",
					Summary:        fmt.Sprintf("system namespace uses PSA enforce=%s without documented justification", enforce),
					Recommendation: "Document why this system namespace needs weaker Pod Security enforcement and review the exception periodically.",
				})
			}
			continue
		}
		if enforce == "baseline" || enforce == "privileged" || enforce == "" {
			severity := SeverityWarning
			if justificationForNamespace(ns) != "" {
				severity = SeverityInfo
			}
			issues = append(issues, Issue{
				Kind:           "Namespace",
				Name:           ns.name,
				Severity:       severity,
				Category:       "security",
				Check:          "psa-weakened-namespace",
				Summary:        fmt.Sprintf("namespace uses weakened Pod Security enforcement (%s)", displayPSALevel(enforce)),
				Recommendation: "Prefer enforce=restricted for application namespaces, and document any baseline or privileged exception with a clear owner and reason.",
			})
		}
	}
	return issues
}

func evaluatePSAPolicyDrift(namespaces map[string]namespaceMeta) []Issue {
	counts := map[string]int{}
	for _, ns := range namespaces {
		if looksLikeSystemNamespace(ns.name) {
			continue
		}
		counts[displayPSALevel(psaLevel(ns.labels, "enforce"))]++
	}
	if len(counts) <= 1 {
		return nil
	}
	parts := make([]string, 0, len(counts))
	for _, key := range sortedMapKeys(counts) {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	severity := SeverityInfo
	if counts["privileged"] > 0 || counts["unlabeled"] > 0 {
		severity = SeverityWarning
	}
	return []Issue{{
		Kind:           "Namespace",
		Name:           "policy-enforcement",
		Severity:       severity,
		Category:       "security",
		Check:          "psa-policy-drift",
		Summary:        fmt.Sprintf("Pod Security enforcement differs across namespaces: %s", strings.Join(parts, ", ")),
		Recommendation: "Standardize Pod Security Admission enforcement levels so namespace policy does not drift without an explicit governance reason.",
	}}
}

func evaluatePodLevelSecurity(pod corev1.Pod, ns namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	flags := make([]string, 0, 3)
	if pod.Spec.HostNetwork {
		flags = append(flags, "hostNetwork")
	}
	if pod.Spec.HostPID {
		flags = append(flags, "hostPID")
	}
	if pod.Spec.HostIPC {
		flags = append(flags, "hostIPC")
	}
	if len(flags) > 0 {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       podSecuritySeverity(ns, SeverityWarning),
			Category:       "security",
			Check:          "pod-security-host-namespace",
			Summary:        fmt.Sprintf("pod enables host namespace access: %s", strings.Join(flags, ", ")),
			Recommendation: "Disable hostNetwork, hostPID, and hostIPC unless the workload is a trusted system component that requires direct host namespace access.",
		})
	}

	hostPaths := make([]string, 0)
	runtimeSockets := make([]string, 0)
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath == nil {
			continue
		}
		hostPaths = append(hostPaths, fmt.Sprintf("%s=%s", volume.Name, volume.HostPath.Path))
		if looksLikeRuntimeSocket(volume.HostPath.Path) {
			runtimeSockets = append(runtimeSockets, volume.HostPath.Path)
		}
	}
	if len(hostPaths) > 0 {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       podSecuritySeverity(ns, SeverityWarning),
			Category:       "security",
			Check:          "pod-security-hostpath",
			Summary:        fmt.Sprintf("pod mounts hostPath volumes: %s", strings.Join(hostPaths, ", ")),
			Recommendation: "Avoid hostPath in application workloads; use CSI volumes or tightly audited node-local mounts only where necessary.",
		})
	}
	if len(runtimeSockets) > 0 {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "pod-security-runtime-socket",
			Summary:        fmt.Sprintf("pod has direct access to runtime socket paths: %s", strings.Join(uniqueStrings(runtimeSockets), ", ")),
			Recommendation: "Remove direct access to container runtime sockets unless this is an explicitly trusted node-management workload.",
		})
	}

	for _, sysctl := range podUnsafeSysctls(pod) {
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       podSecuritySeverity(ns, SeverityWarning),
			Category:       "security",
			Check:          "pod-security-unsafe-sysctl",
			Summary:        fmt.Sprintf("pod configures potentially unsafe sysctl %s=%s", sysctl.Name, sysctl.Value),
			Recommendation: "Allow only safe sysctls and review whether this pod actually needs node-level kernel tuning.",
		})
	}

	if len(pod.Spec.EphemeralContainers) > 0 {
		severity := SeverityWarning
		if isSensitiveWorkload(pod, ns) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "pod-security-ephemeral-container",
			Summary:        fmt.Sprintf("pod has %d ephemeral/debug containers attached", len(pod.Spec.EphemeralContainers)),
			Recommendation: "Review whether debug containers are still required and remove or recreate the workload if sensitive pods should not retain ephemeral debugging access.",
		})
	}

	return issues
}

func evaluateContainerSecurity(pod corev1.Pod, ns namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, container := range allSecurityContainers(pod) {
		ctx := container.securityContext
		if isPrivileged(ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityCritical), "pod-security-privileged", "container runs privileged", "Run the container unprivileged and isolate any host-level operations into a dedicated audited system component."))
		}
		if isAllowPrivilegeEscalation(ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityWarning), "pod-security-allow-privilege-escalation", "container allows privilege escalation", "Set allowPrivilegeEscalation=false unless the container has a verified need for escalated process privileges."))
		}
		if runsAsRoot(pod, ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityWarning), "pod-security-run-as-root", "container is configured to run as root (UID 0)", "Use a non-root user ID for the container and avoid explicit UID 0 unless this is a trusted low-level system component."))
		}
		if !hasRunAsNonRoot(pod, ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityInfo), "pod-security-run-as-non-root", "container does not set runAsNonRoot=true", "Set runAsNonRoot=true so the kubelet can enforce non-root execution at runtime."))
		}
		if dangerous := dangerousCapabilities(ctx); len(dangerous) > 0 {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityWarning), "pod-security-capabilities", fmt.Sprintf("container adds dangerous Linux capabilities: %s", strings.Join(dangerous, ", ")), "Drop dangerous capabilities and keep only the minimum set required, ideally none."))
		}
		if !dropsAllCapabilities(ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityInfo), "pod-security-capabilities-drop", "container does not drop capabilities by default", "Drop ALL capabilities first, then add back only the minimal required ones, such as NET_BIND_SERVICE when justified."))
		}
		if seccompIssue := seccompFinding(pod, ctx); seccompIssue != "" {
			severity := podSecuritySeverity(ns, SeverityWarning)
			if strings.Contains(strings.ToLower(seccompIssue), "unconfined") {
				severity = podSecuritySeverity(ns, SeverityCritical)
			}
			issues = append(issues, podContainerIssue(pod, container, severity, "pod-security-seccomp", seccompIssue, "Use seccompProfile.type=RuntimeDefault or a reviewed Localhost profile for Linux containers."))
		}
		if appArmorIssue := appArmorFinding(pod, ctx); appArmorIssue != "" {
			severity := podSecuritySeverity(ns, SeverityInfo)
			if strings.Contains(strings.ToLower(appArmorIssue), "unconfined") {
				severity = podSecuritySeverity(ns, SeverityWarning)
			}
			issues = append(issues, podContainerIssue(pod, container, severity, "pod-security-apparmor", appArmorIssue, "Use AppArmor RuntimeDefault or a reviewed Localhost profile instead of leaving the workload unconfined."))
		}
		if seLinuxIssue := seLinuxFinding(pod, ctx); seLinuxIssue != "" {
			severity := podSecuritySeverity(ns, SeverityInfo)
			if strings.Contains(strings.ToLower(seLinuxIssue), "weak") || strings.Contains(strings.ToLower(seLinuxIssue), "unconfined") {
				severity = podSecuritySeverity(ns, SeverityWarning)
			}
			issues = append(issues, podContainerIssue(pod, container, severity, "pod-security-selinux", seLinuxIssue, "Use an explicit SELinux confinement policy where supported, and avoid weak or unconfined SELinux types."))
		}
		if isReadOnlyRootFilesystemFalse(ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityWarning), "pod-security-writable-rootfs", "container root filesystem is writable", "Set readOnlyRootFilesystem=true and move writable paths to explicit volumes where possible."))
		} else if !isReadOnlyRootFilesystemTrue(ctx) {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityInfo), "pod-security-readonly-rootfs", "container does not set readOnlyRootFilesystem=true", "Prefer readOnlyRootFilesystem=true for application containers and mount only the directories that must remain writable."))
		}
		if procMountIssue := procMountFinding(ctx); procMountIssue != "" {
			issues = append(issues, podContainerIssue(pod, container, podSecuritySeverity(ns, SeverityWarning), "pod-security-proc-mount", procMountIssue, "Use the default proc mount and avoid unmasked /proc access unless a low-level trusted system component explicitly requires it."))
		}
	}
	return issues
}

func evaluatePSARestrictedViolations(pod corev1.Pod, ns namespaceMeta) []Issue {
	violations := restrictedViolations(pod)
	if len(violations) == 0 {
		return nil
	}
	severity := SeverityWarning
	if psaLevel(ns.labels, "enforce") == "restricted" {
		severity = SeverityCritical
	}
	if isProductionNamespace(ns) {
		severity = SeverityCritical
	}
	preview := violations
	if len(preview) > 5 {
		preview = preview[:5]
	}
	return []Issue{{
		Kind:           "Pod",
		Namespace:      pod.Namespace,
		Name:           pod.Name,
		Severity:       severity,
		Category:       "security",
		Check:          "psa-restricted-violation",
		Summary:        fmt.Sprintf("pod violates restricted Pod Security controls: %s", strings.Join(preview, ", ")),
		Recommendation: "Align the workload with restricted Pod Security requirements or explicitly document and isolate the exception if the workload must remain more privileged.",
		References:     violations,
	}}
}

func allSecurityContainers(pod corev1.Pod) []securityContainerView {
	views := make([]securityContainerView, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers)+len(pod.Spec.EphemeralContainers))
	for _, container := range pod.Spec.InitContainers {
		views = append(views, securityContainerView{kind: "init container", name: container.Name, image: container.Image, securityContext: container.SecurityContext, volumeMounts: container.VolumeMounts})
	}
	for _, container := range pod.Spec.Containers {
		views = append(views, securityContainerView{kind: "container", name: container.Name, image: container.Image, securityContext: container.SecurityContext, volumeMounts: container.VolumeMounts})
	}
	for _, container := range pod.Spec.EphemeralContainers {
		views = append(views, securityContainerView{kind: "ephemeral container", name: container.Name, image: container.Image, securityContext: container.SecurityContext, volumeMounts: container.VolumeMounts})
	}
	return views
}

func podContainerIssue(pod corev1.Pod, container securityContainerView, severity Severity, check, summary, recommendation string) Issue {
	return Issue{
		Kind:           "Pod",
		Namespace:      pod.Namespace,
		Name:           pod.Name,
		Severity:       severity,
		Category:       "security",
		Check:          check,
		Summary:        fmt.Sprintf("%s %s: %s", container.kind, container.name, summary),
		Recommendation: recommendation,
		References:     []string{container.image},
	}
}

func podSecuritySeverity(ns namespaceMeta, base Severity) Severity {
	if !isProductionNamespace(ns) {
		return base
	}
	switch base {
	case SeverityInfo:
		return SeverityWarning
	case SeverityWarning:
		return SeverityCritical
	default:
		return base
	}
}

func isWindowsPod(pod corev1.Pod) bool {
	return pod.Spec.OS != nil && strings.EqualFold(string(pod.Spec.OS.Name), "windows")
}

func isPrivileged(ctx *corev1.SecurityContext) bool {
	return ctx != nil && ctx.Privileged != nil && *ctx.Privileged
}

func isAllowPrivilegeEscalation(ctx *corev1.SecurityContext) bool {
	return ctx != nil && ctx.AllowPrivilegeEscalation != nil && *ctx.AllowPrivilegeEscalation
}

func runsAsRoot(pod corev1.Pod, ctx *corev1.SecurityContext) bool {
	user := effectiveRunAsUser(pod, ctx)
	return user != nil && *user == 0
}

func effectiveRunAsUser(pod corev1.Pod, ctx *corev1.SecurityContext) *int64 {
	if ctx != nil && ctx.RunAsUser != nil {
		return ctx.RunAsUser
	}
	if pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.RunAsUser
	}
	return nil
}

func hasRunAsNonRoot(pod corev1.Pod, ctx *corev1.SecurityContext) bool {
	if ctx != nil && ctx.RunAsNonRoot != nil {
		return *ctx.RunAsNonRoot
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil {
		return *pod.Spec.SecurityContext.RunAsNonRoot
	}
	return false
}

func dangerousCapabilities(ctx *corev1.SecurityContext) []string {
	if ctx == nil || ctx.Capabilities == nil {
		return nil
	}
	dangerousSet := map[string]struct{}{
		"SYS_ADMIN": {}, "NET_ADMIN": {}, "DAC_OVERRIDE": {}, "SYS_PTRACE": {}, "SYS_MODULE": {}, "SYS_RAWIO": {}, "SYS_TIME": {}, "BPF": {}, "PERFMON": {}, "CHECKPOINT_RESTORE": {}, "MKNOD": {}, "SYS_CHROOT": {},
	}
	found := make([]string, 0)
	for _, capability := range ctx.Capabilities.Add {
		capability = corev1.Capability(strings.ToUpper(string(capability)))
		if _, ok := dangerousSet[string(capability)]; ok {
			found = append(found, string(capability))
		}
	}
	return uniqueStrings(found)
}

func dropsAllCapabilities(ctx *corev1.SecurityContext) bool {
	if ctx == nil || ctx.Capabilities == nil {
		return false
	}
	for _, capability := range ctx.Capabilities.Drop {
		if strings.EqualFold(string(capability), "ALL") {
			return true
		}
	}
	return false
}

func seccompFinding(pod corev1.Pod, ctx *corev1.SecurityContext) string {
	profile := effectiveSeccompProfile(pod, ctx)
	if profile == nil {
		return "seccompProfile is not set"
	}
	profileType := string(profile.Type)
	if strings.EqualFold(profileType, "Unconfined") {
		return "seccompProfile is Unconfined"
	}
	if strings.EqualFold(profileType, "Localhost") && (profile.LocalhostProfile == nil || strings.TrimSpace(*profile.LocalhostProfile) == "") {
		return "seccompProfile uses Localhost without specifying a profile name"
	}
	return ""
}

func effectiveSeccompProfile(pod corev1.Pod, ctx *corev1.SecurityContext) *corev1.SeccompProfile {
	if ctx != nil && ctx.SeccompProfile != nil {
		return ctx.SeccompProfile
	}
	if pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.SeccompProfile
	}
	return nil
}

func appArmorFinding(pod corev1.Pod, ctx *corev1.SecurityContext) string {
	profile := effectiveAppArmorProfile(pod, ctx)
	if profile == nil {
		return "AppArmor profile is not set"
	}
	profileType := string(profile.Type)
	if strings.EqualFold(profileType, "Unconfined") {
		return "AppArmor profile is Unconfined"
	}
	if strings.EqualFold(profileType, "Localhost") && (profile.LocalhostProfile == nil || strings.TrimSpace(*profile.LocalhostProfile) == "") {
		return "AppArmor Localhost profile is missing a profile name"
	}
	return ""
}

func effectiveAppArmorProfile(pod corev1.Pod, ctx *corev1.SecurityContext) *corev1.AppArmorProfile {
	if ctx != nil && ctx.AppArmorProfile != nil {
		return ctx.AppArmorProfile
	}
	if pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.AppArmorProfile
	}
	return nil
}

func seLinuxFinding(pod corev1.Pod, ctx *corev1.SecurityContext) string {
	options := effectiveSELinuxOptions(pod, ctx)
	if options == nil {
		return "SELinux profile is not set"
	}
	typ := strings.ToLower(options.Type)
	if typ == "" {
		return "SELinux profile type is not set"
	}
	for _, weak := range []string{"unconfined_t", "spc_t"} {
		if typ == weak {
			return fmt.Sprintf("SELinux profile uses weak type %s", options.Type)
		}
	}
	return ""
}

func effectiveSELinuxOptions(pod corev1.Pod, ctx *corev1.SecurityContext) *corev1.SELinuxOptions {
	if ctx != nil && ctx.SELinuxOptions != nil {
		return ctx.SELinuxOptions
	}
	if pod.Spec.SecurityContext != nil {
		return pod.Spec.SecurityContext.SELinuxOptions
	}
	return nil
}

func isReadOnlyRootFilesystemTrue(ctx *corev1.SecurityContext) bool {
	return ctx != nil && ctx.ReadOnlyRootFilesystem != nil && *ctx.ReadOnlyRootFilesystem
}

func isReadOnlyRootFilesystemFalse(ctx *corev1.SecurityContext) bool {
	return ctx != nil && ctx.ReadOnlyRootFilesystem != nil && !*ctx.ReadOnlyRootFilesystem
}

func procMountFinding(ctx *corev1.SecurityContext) string {
	if ctx == nil || ctx.ProcMount == nil {
		return ""
	}
	if strings.EqualFold(string(*ctx.ProcMount), "Default") {
		return ""
	}
	return fmt.Sprintf("container uses non-default procMount=%s", *ctx.ProcMount)
}

func podUnsafeSysctls(pod corev1.Pod) []corev1.Sysctl {
	if pod.Spec.SecurityContext == nil || len(pod.Spec.SecurityContext.Sysctls) == 0 {
		return nil
	}
	unsafe := make([]corev1.Sysctl, 0)
	for _, sysctl := range pod.Spec.SecurityContext.Sysctls {
		if isSafeSysctl(sysctl.Name) {
			continue
		}
		unsafe = append(unsafe, sysctl)
	}
	return unsafe
}

func isSafeSysctl(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	safe := map[string]struct{}{
		"kernel.shm_rmid_forced":              {},
		"net.ipv4.ip_local_port_range":        {},
		"net.ipv4.ip_unprivileged_port_start": {},
		"net.ipv4.tcp_syncookies":             {},
		"net.ipv4.ping_group_range":           {},
		"net.ipv4.ip_local_reserved_ports":    {},
	}
	_, ok := safe[name]
	return ok
}

func looksLikeRuntimeSocket(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, marker := range []string{"docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock", "podman.sock"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func restrictedViolations(pod corev1.Pod) []string {
	violations := make([]string, 0)
	if pod.Spec.HostNetwork {
		violations = append(violations, "hostNetwork")
	}
	if pod.Spec.HostPID {
		violations = append(violations, "hostPID")
	}
	if pod.Spec.HostIPC {
		violations = append(violations, "hostIPC")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			violations = append(violations, "hostPath")
			break
		}
	}
	if len(podUnsafeSysctls(pod)) > 0 {
		violations = append(violations, "unsafe-sysctls")
	}
	for _, container := range allSecurityContainers(pod) {
		ctx := container.securityContext
		if isPrivileged(ctx) {
			violations = append(violations, container.name+":privileged")
		}
		if ctx == nil || ctx.AllowPrivilegeEscalation == nil || *ctx.AllowPrivilegeEscalation {
			violations = append(violations, container.name+":allowPrivilegeEscalation")
		}
		if !hasRunAsNonRoot(pod, ctx) {
			violations = append(violations, container.name+":runAsNonRoot")
		}
		if runsAsRoot(pod, ctx) {
			violations = append(violations, container.name+":runAsUser=0")
		}
		if dangerous := dangerousCapabilities(ctx); len(dangerous) > 0 {
			violations = append(violations, container.name+":dangerous-capabilities")
		}
		if !dropsAllCapabilities(ctx) {
			violations = append(violations, container.name+":drop-ALL")
		}
		if profile := effectiveSeccompProfile(pod, ctx); profile == nil || strings.EqualFold(string(profile.Type), "Unconfined") {
			violations = append(violations, container.name+":seccomp")
		}
		if profile := effectiveAppArmorProfile(pod, ctx); profile == nil || strings.EqualFold(string(profile.Type), "Unconfined") {
			violations = append(violations, container.name+":apparmor")
		}
		if ctx != nil && ctx.ProcMount != nil && !strings.EqualFold(string(*ctx.ProcMount), "Default") {
			violations = append(violations, container.name+":procMount")
		}
	}
	return uniqueStrings(violations)
}

func psaLevel(labels map[string]string, mode string) string {
	if labels == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(labels["pod-security.kubernetes.io/"+mode]))
}

func isValidPSALevel(level string) bool {
	return level == "restricted" || level == "baseline" || level == "privileged"
}

func displayPSALevel(level string) string {
	if level == "" {
		return "unlabeled"
	}
	return level
}

func looksLikeSystemNamespace(name string) bool {
	if isSystemNamespace(name) {
		return true
	}
	name = strings.ToLower(name)
	if strings.HasSuffix(name, "-system") || strings.HasSuffix(name, "-security") || strings.HasSuffix(name, "-monitoring") {
		return true
	}
	for _, marker := range []string{"istio-system", "gatekeeper-system", "cattle-system", "monitoring", "kyverno", "cert-manager", "tigera-operator", "openshift"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func justificationForNamespace(ns namespaceMeta) string {
	for _, source := range []map[string]string{ns.labels, ns.annotations} {
		for key, value := range source {
			key = strings.ToLower(key)
			if value == "" {
				continue
			}
			for _, marker := range []string{"justification", "reason", "owner", "ticket", "exception", "risk", "waiver"} {
				if strings.Contains(key, marker) {
					return value
				}
			}
		}
	}
	return ""
}

func isSensitiveWorkload(pod corev1.Pod, ns namespaceMeta) bool {
	if looksLikeSystemNamespace(pod.Namespace) || isProductionNamespace(ns) {
		return true
	}
	fields := []string{pod.Name, pod.Namespace}
	for key, value := range pod.Labels {
		fields = append(fields, key, value)
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"auth", "identity", "payment", "secret", "vault", "cert", "token", "gateway", "ingress", "controller"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func sortedNamespaceMeta(namespaces map[string]namespaceMeta) []namespaceMeta {
	items := make([]namespaceMeta, 0, len(namespaces))
	for _, ns := range namespaces {
		items = append(items, ns)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].name < items[j].name })
	return items
}

func sortedMapKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
