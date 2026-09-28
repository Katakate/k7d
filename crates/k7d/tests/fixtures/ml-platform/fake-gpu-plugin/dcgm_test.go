package main

import (
	"strings"
	"testing"
)

func TestFormatDcgmPodLabelsAndOverride(t *testing.T) {
	assigned := map[string]assign{
		"fake-gpu-0": {namespace: "default", name: "dcgm-pod-a", container: "busybox"},
	}
	lookup := func(ns, name string) (map[string]string, error) {
		if ns == "default" && name == "dcgm-pod-a" {
			return map[string]string{annGPUUtil: "77"}, nil
		}
		t.Fatalf("unexpected lookup %s/%s", ns, name)
		return nil, nil
	}
	body, err := formatDcgm(2, "k7d-10-200-0-2", defaultGPUUtil, defaultFBUsed, assigned, lookup)
	if err != nil {
		t.Fatal(err)
	}
	wantUtilA := `DCGM_FI_DEV_GPU_UTIL{gpu="fake-gpu-0",UUID="GPU-fake-0",device="nvidia0",modelName="Fake-A100",Hostname="k7d-10-200-0-2",namespace="default",pod="dcgm-pod-a",container="busybox"} 77`
	wantUtilB := `DCGM_FI_DEV_GPU_UTIL{gpu="fake-gpu-1",UUID="GPU-fake-1",device="nvidia1",modelName="Fake-A100",Hostname="k7d-10-200-0-2"} 42`
	wantFbA := `DCGM_FI_DEV_FB_USED{gpu="fake-gpu-0",UUID="GPU-fake-0",device="nvidia0",modelName="Fake-A100",Hostname="k7d-10-200-0-2",namespace="default",pod="dcgm-pod-a",container="busybox"} 1024`
	wantFbB := `DCGM_FI_DEV_FB_USED{gpu="fake-gpu-1",UUID="GPU-fake-1",device="nvidia1",modelName="Fake-A100",Hostname="k7d-10-200-0-2"} 1024`
	for _, want := range []string{wantUtilA, wantUtilB, wantFbA, wantFbB} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s\nbody:\n%s", want, body)
		}
	}
	if strings.Contains(body, `gpu="fake-gpu-1",UUID="GPU-fake-1",device="nvidia1",modelName="Fake-A100",Hostname="k7d-10-200-0-2",pod=`) {
		t.Fatalf("unassigned series has pod label:\n%s", body)
	}
}

func TestFormatDcgmDropsLabelsWhenPodIsGone(t *testing.T) {
	assigned := map[string]assign{
		"fake-gpu-0": {namespace: "default", name: "dcgm-pod-a", container: "busybox"},
	}
	lookup := func(string, string) (map[string]string, error) {
		return nil, errPodGone
	}
	body, err := formatDcgm(2, "node", "42", "1024", assigned, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "pod=") || strings.Contains(body, "namespace=") {
		t.Fatalf("deleted pod still labeled:\n%s", body)
	}
	if !strings.Contains(body, `gpu="fake-gpu-0"`) || !strings.Contains(body, `gpu="fake-gpu-1"`) {
		t.Fatalf("missing device series:\n%s", body)
	}
}

func TestFormatDcgmRejectsUnknownID(t *testing.T) {
	assigned := map[string]assign{
		"not-a-gpu": {namespace: "default", name: "p", container: "c"},
	}
	_, err := formatDcgm(2, "node", "42", "1024", assigned, func(string, string) (map[string]string, error) {
		t.Fatal("lookup should not run")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
