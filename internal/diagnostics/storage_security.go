package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	volumeSnapshotGVR      = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
	volumeSnapshotClassGVR = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}
)

type pvcUsageView struct {
	pods        []string
	controllers map[string]struct{}
}

func CheckStorageSecurity(ctx context.Context, cs *kubernetes.Clientset, dyn dynamic.Interface, namespace string) ([]Issue, error) {
	if cs == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	namespaces, err := listNamespaceMeta(ctx, cs, namespace)
	if err != nil {
		return nil, err
	}
	pvcs, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pvs, err := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	storageClasses, err := cs.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	daemonsets, err := cs.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	storageClassIndex := make(map[string]storagev1.StorageClass, len(storageClasses.Items))
	for _, class := range storageClasses.Items {
		storageClassIndex[class.Name] = class
	}
	usage := pvcUsageByWorkload(pods.Items)

	issues := make([]Issue, 0)
	issues = append(issues, pvcBroadAccessIssues(pvcs.Items, namespaces)...)
	issues = append(issues, storageClassEncryptionIssues(storageClasses.Items)...)
	issues = append(issues, persistentVolumeEncryptionIssues(pvs.Items, storageClassIndex)...)
	issues = append(issues, csiDriverPrivilegeIssues(daemonsets.Items)...)
	issues = append(issues, sharedRWXVolumeIssues(pvcs.Items, usage)...)
	issues = append(issues, sensitiveHostPathStorageIssues(pods.Items)...)
	issues = append(issues, sensitivePVCStorageClassIssues(pvcs.Items, storageClassIndex, namespaces)...)
	issues = append(issues, oldSensitiveVolumeIssues(pvs.Items, storageClassIndex)...)
	issues = append(issues, reclaimPolicyLeakageIssues(pvs.Items, storageClassIndex)...)
	issues = append(issues, volumeSnapshotSecurityIssues(ctx, dyn, ns, namespaces)...)

	return dedupeIssues(issues), nil
}

func pvcBroadAccessIssues(pvcs []corev1.PersistentVolumeClaim, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pvc := range pvcs {
		if !pvcHasBroadAccessModes(pvc.Spec.AccessModes) {
			continue
		}
		severity := SeverityWarning
		if pvcLooksSensitive(pvc) || isProductionNamespace(namespaces[pvc.Namespace]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "PVC",
			Namespace:      pvc.Namespace,
			Name:           pvc.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "storage-broad-access-mode",
			Summary:        fmt.Sprintf("PVC uses broad access modes: %s", joinAccessModes(pvc.Spec.AccessModes)),
			Recommendation: "Prefer the narrowest possible access mode, and avoid RWX for sensitive or single-workload data unless shared write access is explicitly required.",
		})
	}
	return issues
}

func storageClassEncryptionIssues(classes []storagev1.StorageClass) []Issue {
	issues := make([]Issue, 0)
	for _, class := range classes {
		if storageClassLooksEncrypted(class) {
			continue
		}
		severity := SeverityInfo
		if storageClassLooksCloudBacked(class) {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "StorageClass",
			Name:           class.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "storageclass-encryption-unverified",
			Summary:        fmt.Sprintf("storage class %s does not show obvious encryption settings", class.Name),
			Recommendation: "Enable volume encryption or document how encryption-at-rest is enforced for this storage class and its backing storage backend.",
		})
		if storageTargetLooksPublic(class.Parameters, class.Annotations) {
			issues = append(issues, Issue{
				Kind:           "StorageClass",
				Name:           class.Name,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "storageclass-public-backup-target",
				Summary:        "storage class parameters or annotations reference a possibly public backup/object target",
				Recommendation: "Review bucket, container, and snapshot export settings so backups and volume exports are not world-readable or anonymously accessible.",
			})
		}
	}
	return issues
}

func persistentVolumeEncryptionIssues(volumes []corev1.PersistentVolume, classes map[string]storagev1.StorageClass) []Issue {
	issues := make([]Issue, 0)
	for _, volume := range volumes {
		class := classes[volume.Spec.StorageClassName]
		if persistentVolumeLooksEncrypted(volume, class) {
			continue
		}
		severity := SeverityInfo
		if persistentVolumeLooksSensitive(volume) || volume.Spec.ClaimRef != nil {
			severity = SeverityWarning
		}
		issues = append(issues, Issue{
			Kind:           "PV",
			Name:           volume.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "pv-encryption-unverified",
			Summary:        fmt.Sprintf("persistent volume %s does not show obvious encryption-at-rest settings", volume.Name),
			Recommendation: "Use encrypted volume backends or explicitly document volume encryption guarantees for this PV and its storage class.",
		})
	}
	return issues
}

func csiDriverPrivilegeIssues(daemonsets []appsv1.DaemonSet) []Issue {
	issues := make([]Issue, 0)
	for _, ds := range daemonsets {
		if !looksLikeCSIDriver(ds) {
			continue
		}
		if !daemonSetTemplateLooksPrivileged(ds.Spec.Template.Spec) {
			continue
		}
		severity := SeverityWarning
		if !isSystemNamespace(ds.Namespace) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "DaemonSet",
			Namespace:      ds.Namespace,
			Name:           ds.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "csi-driver-privileged",
			Summary:        "CSI driver runs with broad host privileges or host filesystem access",
			Recommendation: "Review whether this CSI driver really needs privileged mode, host networking, and broad hostPath mounts, and keep CSI components in tightly controlled system namespaces only.",
		})
	}
	return issues
}

func sharedRWXVolumeIssues(pvcs []corev1.PersistentVolumeClaim, usage map[string]pvcUsageView) []Issue {
	issues := make([]Issue, 0)
	for _, pvc := range pvcs {
		if !hasAccessMode(pvc.Spec.AccessModes, corev1.ReadWriteMany) {
			continue
		}
		view := usage[pvc.Namespace+"/"+pvc.Name]
		if len(view.controllers) <= 1 && len(view.pods) <= 1 {
			continue
		}
		controllers := make([]string, 0, len(view.controllers))
		for key := range view.controllers {
			controllers = append(controllers, key)
		}
		sort.Strings(controllers)
		issues = append(issues, Issue{
			Kind:           "PVC",
			Namespace:      pvc.Namespace,
			Name:           pvc.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "storage-shared-rwx",
			Summary:        fmt.Sprintf("RWX volume is shared across multiple workloads: %s", strings.Join(controllers, ", ")),
			Recommendation: "Verify the data-sharing boundary is intentional; shared writeable volumes between unrelated workloads increase the chance of lateral movement and data leakage.",
		})
	}
	return issues
}

func sensitiveHostPathStorageIssues(pods []corev1.Pod) []Issue {
	issues := make([]Issue, 0)
	for _, pod := range pods {
		paths := make([]string, 0)
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath == nil || volume.HostPath.Path == "" {
				continue
			}
			if sensitiveNodeHostPath(volume.HostPath.Path) || looksLikeRuntimeSocket(volume.HostPath.Path) {
				paths = append(paths, volume.HostPath.Path)
			}
		}
		if len(paths) == 0 {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "Pod",
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Severity:       SeverityCritical,
			Category:       "security",
			Check:          "storage-sensitive-hostpath",
			Summary:        fmt.Sprintf("workload mounts sensitive host storage paths: %s", strings.Join(uniqueStrings(paths), ", ")),
			Recommendation: "Remove hostPath access to /etc, /root, /var/lib/kubelet, runtime sockets, and similar node paths unless this is a tightly controlled node-management workload.",
		})
	}
	return issues
}

func sensitivePVCStorageClassIssues(pvcs []corev1.PersistentVolumeClaim, classes map[string]storagev1.StorageClass, namespaces map[string]namespaceMeta) []Issue {
	issues := make([]Issue, 0)
	for _, pvc := range pvcs {
		if !pvcLooksSensitive(pvc) {
			continue
		}
		className := pointerString(pvc.Spec.StorageClassName)
		class, ok := classes[className]
		if !ok || storageClassLooksEncrypted(class) {
			continue
		}
		severity := SeverityWarning
		if isProductionNamespace(namespaces[pvc.Namespace]) {
			severity = SeverityCritical
		}
		issues = append(issues, Issue{
			Kind:           "PVC",
			Namespace:      pvc.Namespace,
			Name:           pvc.Name,
			Severity:       severity,
			Category:       "security",
			Check:          "storage-sensitive-pvc-insecure-class",
			Summary:        fmt.Sprintf("sensitive data volume uses storage class %s without obvious encryption settings", className),
			Recommendation: "Move secrets, config state, databases, and backups to encrypted storage classes with clear retention and access controls.",
		})
	}
	return issues
}

func oldSensitiveVolumeIssues(volumes []corev1.PersistentVolume, classes map[string]storagev1.StorageClass) []Issue {
	issues := make([]Issue, 0)
	cutoff := 30 * 24 * time.Hour
	for _, volume := range volumes {
		if volume.Status.Phase != corev1.VolumeAvailable && volume.Status.Phase != corev1.VolumeReleased {
			continue
		}
		age := time.Since(volume.CreationTimestamp.Time)
		if age < cutoff {
			continue
		}
		if !persistentVolumeLooksSensitive(volume) && storageClassLooksEncrypted(classes[volume.Spec.StorageClassName]) {
			continue
		}
		issues = append(issues, Issue{
			Kind:           "PV",
			Name:           volume.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "storage-old-unattached-volume",
			Summary:        fmt.Sprintf("old unattached volume may still contain sensitive data (%s old, phase=%s)", humanDuration(age), volume.Status.Phase),
			Recommendation: "Review old released or available volumes for residual data, snapshot sprawl, and forgotten backups, then wipe or delete them if no longer needed.",
		})
	}
	return issues
}

func reclaimPolicyLeakageIssues(volumes []corev1.PersistentVolume, classes map[string]storagev1.StorageClass) []Issue {
	issues := make([]Issue, 0)
	for _, volume := range volumes {
		if volume.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain {
			continue
		}
		if !persistentVolumeLooksSensitive(volume) && volume.Status.Phase != corev1.VolumeReleased {
			continue
		}
		className := volume.Spec.StorageClassName
		issues = append(issues, Issue{
			Kind:           "PV",
			Name:           volume.Name,
			Severity:       SeverityWarning,
			Category:       "security",
			Check:          "storage-reclaim-retain-leakage",
			Summary:        fmt.Sprintf("PV keeps reclaimPolicy=Retain and may leak residual data (storageClass=%s)", className),
			Recommendation: "Use Retain only with explicit wipe and ownership handoff procedures; otherwise prefer Delete for ephemeral or tenant-isolated data.",
		})
	}
	return issues
}

func volumeSnapshotSecurityIssues(ctx context.Context, dyn dynamic.Interface, namespace string, namespaces map[string]namespaceMeta) []Issue {
	if dyn == nil {
		return nil
	}
	var (
		snapshots *unstructured.UnstructuredList
		err       error
	)
	if namespace != metav1.NamespaceAll {
		snapshots, err = dyn.Resource(volumeSnapshotGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	} else {
		snapshots, err = dyn.Resource(volumeSnapshotGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil
	}
	classes, err := dyn.Resource(volumeSnapshotClassGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		classes = &unstructured.UnstructuredList{}
	}
	classIndex := make(map[string]unstructured.Unstructured, len(classes.Items))
	for _, class := range classes.Items {
		classIndex[class.GetName()] = class
	}
	issues := make([]Issue, 0)
	for _, snapshot := range snapshots.Items {
		ns := snapshot.GetNamespace()
		name := snapshot.GetName()
		className := nestedStringMapValue(snapshot.Object, "spec", "volumeSnapshotClassName")
		class := classIndex[className]
		sourcePVC := nestedStringMapValue(snapshot.Object, "spec", "source", "persistentVolumeClaimName")
		deletionPolicy := nestedStringMapValue(class.Object, "deletionPolicy")
		if deletionPolicy == "Retain" && (looksSensitiveStorageName(name) || looksSensitiveStorageName(sourcePVC) || isProductionNamespace(namespaces[ns])) {
			issues = append(issues, Issue{
				Kind:           "VolumeSnapshot",
				Namespace:      ns,
				Name:           name,
				Severity:       SeverityWarning,
				Category:       "security",
				Check:          "snapshot-retention-sensitive",
				Summary:        fmt.Sprintf("volume snapshot retains sensitive data after deletion (class=%s)", className),
				Recommendation: "Use explicit retention governance and wipe/expiration processes for snapshots that capture secrets, databases, or tenant data.",
			})
		}
		if storageTargetLooksPublic(anyMapToStringMap(class.Object["parameters"]), class.GetAnnotations()) {
			issues = append(issues, Issue{
				Kind:           "VolumeSnapshotClass",
				Name:           className,
				Severity:       SeverityCritical,
				Category:       "security",
				Check:          "snapshot-public-target",
				Summary:        "snapshot class appears to reference a public or broadly accessible backup target",
				Recommendation: "Ensure snapshot exports and backup buckets are private, authenticated, and tenant-scoped.",
			})
		}
	}
	return issues
}

func pvcUsageByWorkload(pods []corev1.Pod) map[string]pvcUsageView {
	usage := make(map[string]pvcUsageView)
	for _, pod := range pods {
		controller := pod.Name
		if len(pod.OwnerReferences) > 0 {
			controller = pod.OwnerReferences[0].Kind + "/" + pod.OwnerReferences[0].Name
		}
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim == nil {
				continue
			}
			key := pod.Namespace + "/" + volume.PersistentVolumeClaim.ClaimName
			view := usage[key]
			if view.controllers == nil {
				view.controllers = map[string]struct{}{}
			}
			view.controllers[controller] = struct{}{}
			view.pods = append(view.pods, pod.Name)
			usage[key] = view
		}
	}
	return usage
}

func pvcHasBroadAccessModes(modes []corev1.PersistentVolumeAccessMode) bool {
	return hasAccessMode(modes, corev1.ReadWriteMany) || len(modes) > 1
}

func hasAccessMode(modes []corev1.PersistentVolumeAccessMode, expected corev1.PersistentVolumeAccessMode) bool {
	for _, mode := range modes {
		if mode == expected {
			return true
		}
	}
	return false
}

func joinAccessModes(modes []corev1.PersistentVolumeAccessMode) string {
	values := make([]string, 0, len(modes))
	for _, mode := range modes {
		values = append(values, string(mode))
	}
	return strings.Join(values, ", ")
}

func storageClassLooksCloudBacked(class storagev1.StorageClass) bool {
	text := strings.ToLower(class.Provisioner)
	for _, marker := range []string{"ebs", "efs", "gce", "pd.csi", "azure", "disk.csi", "file.csi", "ceph", "cinder", "vsphere", "longhorn", "nfs", "csi"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func storageClassLooksEncrypted(class storagev1.StorageClass) bool {
	if len(class.Parameters) == 0 && len(class.Annotations) == 0 {
		return false
	}
	return storageMapLooksEncrypted(class.Parameters) || storageMapLooksEncrypted(class.Annotations)
}

func storageMapLooksEncrypted(values map[string]string) bool {
	for key, value := range values {
		combined := strings.ToLower(key + "=" + value)
		for _, marker := range []string{"encrypted=true", "encryption=true", "kms", "cmk", "disk-encryption-set", "customer-managed-key", "customermanagedkey", "keyring", "luks", "sse", "server-side-encryption"} {
			if strings.Contains(combined, marker) {
				return true
			}
		}
	}
	return false
}

func persistentVolumeLooksEncrypted(volume corev1.PersistentVolume, class storagev1.StorageClass) bool {
	if storageClassLooksEncrypted(class) {
		return true
	}
	if volume.Spec.CSI != nil {
		attrs := map[string]string{}
		for key, value := range volume.Spec.CSI.VolumeAttributes {
			attrs[key] = value
		}
		if storageMapLooksEncrypted(attrs) {
			return true
		}
	}
	if volume.Spec.AWSElasticBlockStore != nil || volume.Spec.GCEPersistentDisk != nil || volume.Spec.AzureDisk != nil || volume.Spec.Cinder != nil {
		return false
	}
	return false
}

func looksLikeCSIDriver(ds appsv1.DaemonSet) bool {
	fields := []string{ds.Name, ds.Namespace}
	for _, container := range append(append([]corev1.Container{}, ds.Spec.Template.Spec.InitContainers...), ds.Spec.Template.Spec.Containers...) {
		fields = append(fields, container.Name, container.Image)
	}
	for _, field := range fields {
		text := strings.ToLower(field)
		for _, marker := range []string{"csi", "node-driver-registrar", "external-provisioner", "external-attacher", "external-resizer", "snapshotter"} {
			if strings.Contains(text, marker) {
				return true
			}
		}
	}
	return false
}

func pvcLooksSensitive(pvc corev1.PersistentVolumeClaim) bool {
	fields := []string{pvc.Name, pvc.Namespace}
	for _, source := range []map[string]string{pvc.Labels, pvc.Annotations} {
		for key, value := range source {
			fields = append(fields, key, value)
		}
	}
	for _, field := range fields {
		if looksSensitiveStorageName(field) {
			return true
		}
	}
	return false
}

func persistentVolumeLooksSensitive(volume corev1.PersistentVolume) bool {
	fields := []string{volume.Name, volume.Spec.StorageClassName}
	if volume.Spec.ClaimRef != nil {
		fields = append(fields, volume.Spec.ClaimRef.Namespace, volume.Spec.ClaimRef.Name)
	}
	for _, field := range fields {
		if looksSensitiveStorageName(field) {
			return true
		}
	}
	return false
}

func looksSensitiveStorageName(value string) bool {
	text := strings.ToLower(value)
	for _, marker := range []string{"secret", "config", "vault", "token", "cert", "key", "backup", "db", "database", "postgres", "mysql", "mongo", "redis", "tenant", "home", "userdata"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func storageTargetLooksPublic(parameters map[string]string, annotations map[string]string) bool {
	for _, source := range []map[string]string{parameters, annotations} {
		for key, value := range source {
			combined := strings.ToLower(key + "=" + value)
			for _, marker := range []string{"public", "allusers", "anonymous", "public-read", "bucket-policy=*", "acl=public", "world-readable"} {
				if strings.Contains(combined, marker) {
					return true
				}
			}
		}
	}
	return false
}

func anyMapToStringMap(value any) map[string]string {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]string); ok {
		return typed
	}
	source, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, item := range source {
		result[key] = fmt.Sprintf("%v", item)
	}
	return result
}
