package diagnostics

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CheckStorage(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]Issue, error) {
	ns := namespace
	if ns == "" {
		ns = metav1.NamespaceAll
	}

	var issues []Issue

	pvcs, err := cs.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, pvc := range pvcs.Items {
		if pvc.Status.Phase == corev1.ClaimPending {
			issues = append(issues, Issue{
				Kind:           "PVC",
				Namespace:      pvc.Namespace,
				Name:           pvc.Name,
				Severity:       SeverityCritical,
				Category:       "storage",
				Check:          "pvc-binding",
				Summary:        "persistent volume claim is still Pending",
				Recommendation: "Check matching StorageClass, PV availability, access modes, and CSI provisioner health.",
			})
		}
		if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName == "" {
			issues = append(issues, Issue{
				Kind:           "PVC",
				Namespace:      pvc.Namespace,
				Name:           pvc.Name,
				Severity:       SeverityInfo,
				Category:       "storage",
				Check:          "pvc-storageclass",
				Summary:        "persistent volume claim has no explicit StorageClass",
				Recommendation: "Confirm the cluster has a default StorageClass or set storageClassName explicitly.",
			})
		}
	}

	pvs, err := cs.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, pv := range pvs.Items {
		switch pv.Status.Phase {
		case corev1.VolumeReleased, corev1.VolumeFailed:
			issues = append(issues, Issue{
				Kind:           "PV",
				Name:           pv.Name,
				Severity:       SeverityWarning,
				Category:       "storage",
				Check:          "pv-phase",
				Summary:        fmt.Sprintf("persistent volume in phase %s", pv.Status.Phase),
				Recommendation: "Inspect reclaim policy, volume attachments, and CSI controller logs.",
			})
		case corev1.VolumeAvailable:
			if pv.Spec.ClaimRef == nil {
				issues = append(issues, Issue{
					Kind:           "PV",
					Name:           pv.Name,
					Severity:       SeverityInfo,
					Category:       "storage",
					Check:          "pv-orphaned",
					Summary:        "persistent volume is available but not bound",
					Recommendation: "Verify this PV is still needed or remove it to avoid stale capacity accounting.",
				})
			}
		}
	}

	storageClasses, err := cs.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err == nil && len(storageClasses.Items) == 0 {
		issues = append(issues, Issue{
			Kind:           "StorageClass",
			Severity:       SeverityWarning,
			Category:       "storage",
			Check:          "storageclass-missing",
			Summary:        "no StorageClass resources found",
			Recommendation: "Install or restore a provisioner-backed StorageClass if workloads rely on dynamic provisioning.",
		})
	}

	attachments, err := cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, attachment := range attachments.Items {
			if attachment.Status.Attached {
				continue
			}
			msg := "volume attachment is not attached"
			if attachment.Status.AttachError != nil && attachment.Status.AttachError.Message != "" {
				msg = fmt.Sprintf("volume attachment failed: %s", attachment.Status.AttachError.Message)
			}
			issues = append(issues, Issue{
				Kind:           "PV",
				Name:           attachment.Name,
				Severity:       SeverityWarning,
				Category:       "storage",
				Check:          "volume-attachment",
				Summary:        msg,
				Recommendation: "Check CSI controller/node logs, node readiness, and storage backend connectivity.",
			})
		}
	}

	return issues, nil
}
