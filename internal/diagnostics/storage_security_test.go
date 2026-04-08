package diagnostics

import (
	"context"
	"net/http"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestStorageSecurityHelpersAndCheckStorageSecurity(t *testing.T) {
	now := time.Now()
	class := storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "standard", Annotations: map[string]string{"bucket": "public-read"}}, Provisioner: "ebs.csi.aws.com"}
	pvc := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "db-pvc", Namespace: "prod"}, Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}, StorageClassName: func() *string { s := "standard"; return &s }()}}
	pv := corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "db-pv", CreationTimestamp: metav1.NewTime(now.Add(-45 * 24 * time.Hour))}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "standard", PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain, ClaimRef: &corev1.ObjectReference{Name: "db-pvc", Namespace: "prod"}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased}}
	privileged := true
	daemonset := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "ebs-csi-node", Namespace: "prod"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "csi", Image: "ebs-csi", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}},
		}}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod", Labels: map[string]string{"app": "api"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}}},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "host", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet/pki"}}},
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "db-pvc"}}},
		}},
	}

	if len(pvcBroadAccessIssues([]corev1.PersistentVolumeClaim{pvc}, map[string]namespaceMeta{"prod": {name: "prod"}})) == 0 || len(storageClassEncryptionIssues([]storagev1.StorageClass{class})) < 2 {
		t.Fatal("expected PVC and storageclass issues")
	}
	if len(persistentVolumeEncryptionIssues([]corev1.PersistentVolume{pv}, map[string]storagev1.StorageClass{"standard": class})) == 0 || len(csiDriverPrivilegeIssues([]appsv1.DaemonSet{daemonset})) == 0 {
		t.Fatal("expected PV and CSI issues")
	}
	usage := pvcUsageByWorkload([]corev1.Pod{pod, {
		ObjectMeta: metav1.ObjectMeta{Name: "api-2", Namespace: "prod", OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db"}}},
		Spec:       corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "db-pvc"}}}}},
	}})
	if len(sharedRWXVolumeIssues([]corev1.PersistentVolumeClaim{pvc}, usage)) == 0 || len(sensitiveHostPathStorageIssues([]corev1.Pod{pod})) == 0 {
		t.Fatal("expected shared RWX and hostPath issues")
	}
	if len(sensitivePVCStorageClassIssues([]corev1.PersistentVolumeClaim{pvc}, map[string]storagev1.StorageClass{"standard": class}, map[string]namespaceMeta{"prod": {name: "prod"}})) == 0 || len(oldSensitiveVolumeIssues([]corev1.PersistentVolume{pv}, map[string]storagev1.StorageClass{"standard": class})) == 0 || len(reclaimPolicyLeakageIssues([]corev1.PersistentVolume{pv}, map[string]storagev1.StorageClass{"standard": class})) == 0 {
		t.Fatal("expected sensitive storage issues")
	}
	if !pvcHasBroadAccessModes(pvc.Spec.AccessModes) || !hasAccessMode(pvc.Spec.AccessModes, corev1.ReadWriteMany) || joinAccessModes(pvc.Spec.AccessModes) == "" {
		t.Fatal("unexpected access mode helper behavior")
	}
	if !storageClassLooksCloudBacked(class) || storageClassLooksEncrypted(class) || !storageTargetLooksPublic(class.Parameters, class.Annotations) {
		t.Fatal("unexpected storage class helper behavior")
	}
	if persistentVolumeLooksEncrypted(pv, class) || !looksLikeCSIDriver(daemonset) || !pvcLooksSensitive(pvc) || !persistentVolumeLooksSensitive(pv) || !looksSensitiveStorageName("db-backup") {
		t.Fatal("unexpected storage detection helper behavior")
	}
	if anyMapToStringMap(map[string]any{"x": 1})["x"] != "1" {
		t.Fatal("expected generic map conversion")
	}

	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), &unstructured.Unstructured{
		Object: map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot", "metadata": map[string]any{"name": "db-snapshot", "namespace": "prod"}, "spec": map[string]any{"volumeSnapshotClassName": "snapclass", "source": map[string]any{"persistentVolumeClaimName": "db-pvc"}}},
	}, &unstructured.Unstructured{
		Object: map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass", "metadata": map[string]any{"name": "snapclass", "annotations": map[string]any{"bucket": "public"}}, "deletionPolicy": "Retain", "parameters": map[string]any{"acl": "public-read"}},
	})
	if len(volumeSnapshotSecurityIssues(context.Background(), dyn, "prod", map[string]namespaceMeta{"prod": {name: "prod"}})) == 0 {
		t.Fatal("expected snapshot security issues")
	}

	ctx := context.Background()
	cs := newHTTPBackedClientset(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod":
			writeJSONResponse(t, w, http.StatusOK, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", Labels: map[string]string{"environment": "production"}}})
		case "/api/v1/namespaces/prod/persistentvolumeclaims":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{pvc}})
		case "/api/v1/persistentvolumes":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PersistentVolumeList{Items: []corev1.PersistentVolume{pv}})
		case "/apis/storage.k8s.io/v1/storageclasses":
			writeJSONResponse(t, w, http.StatusOK, &storagev1.StorageClassList{Items: []storagev1.StorageClass{class}})
		case "/api/v1/namespaces/prod/pods":
			writeJSONResponse(t, w, http.StatusOK, &corev1.PodList{Items: []corev1.Pod{pod}})
		case "/apis/apps/v1/daemonsets":
			writeJSONResponse(t, w, http.StatusOK, &appsv1.DaemonSetList{Items: []appsv1.DaemonSet{daemonset}})
		default:
			writeJSONResponse(t, w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
	issues, err := CheckStorageSecurity(ctx, cs, dyn, "prod")
	if err != nil {
		t.Fatalf("CheckStorageSecurity returned error: %v", err)
	}
	if len(issues) < 6 {
		t.Fatalf("expected storage security issues, got %+v", issues)
	}
	if _, err := CheckStorageSecurity(ctx, nil, dyn, "prod"); err == nil {
		t.Fatal("expected nil clientset to fail")
	}
}
