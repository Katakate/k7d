// Per-device fake DCGM text. Not NVML.
//
// One series per fake-gpu-N. pod / namespace / container come from
// the kubelet pod-resources list. When that pod is gone, those labels
// are omitted.
//
// Values: FAKE_DCGM_GPU_UTIL (default 42) and FAKE_DCGM_FB_USED
// (default 1024). A pod annotation overrides that device only:
//
//	k7d.katakate.org/fake-dcgm-gpu-util
//	k7d.katakate.org/fake-dcgm-fb-used
//
// Unset env or a missing annotation uses the default. A set-but-invalid
// number fails the render.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGPUUtil = "42"
	defaultFBUsed  = "1024"
	annGPUUtil     = "k7d.katakate.org/fake-dcgm-gpu-util"
	annFBUsed      = "k7d.katakate.org/fake-dcgm-fb-used"
	dcgmModelName  = "Fake-A100"
)

var errPodGone = errors.New("pod not found")

type assign struct {
	namespace string
	name      string
	container string
}

func renderDcgm() {
	count := fakeGpuCount()
	hostname := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if hostname == "" {
		log.Fatal("NODE_NAME is empty")
	}
	utilDefault := envNumber("FAKE_DCGM_GPU_UTIL", defaultGPUUtil)
	fbDefault := envNumber("FAKE_DCGM_FB_USED", defaultFBUsed)
	rows, err := fetchPodResources()
	if err != nil {
		log.Fatal(err)
	}
	assigned, err := gpuAssignments(rows)
	if err != nil {
		log.Fatal(err)
	}
	body, err := formatDcgm(count, hostname, utilDefault, fbDefault, assigned, podAnnotations)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stdout.WriteString(body); err != nil {
		log.Fatal(err)
	}
}

func envNumber(key, def string) string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	if err := finiteNumber(raw); err != nil {
		log.Fatalf("%s=%q: %v", key, raw, err)
	}
	return raw
}

func finiteNumber(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("want a finite number")
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return fmt.Errorf("want a finite number")
	}
	return nil
}

func gpuAssignments(rows []podResourceRow) (map[string]assign, error) {
	out := make(map[string]assign)
	for _, r := range rows {
		if r.Resource != resourceName {
			continue
		}
		for _, id := range r.IDs {
			if prev, ok := out[id]; ok {
				return nil, fmt.Errorf(
					"device %s assigned to %s/%s/%s and %s/%s/%s",
					id, prev.namespace, prev.name, prev.container,
					r.Namespace, r.Name, r.Container,
				)
			}
			out[id] = assign{namespace: r.Namespace, name: r.Name, container: r.Container}
		}
	}
	return out, nil
}

func deviceIndex(id string) (int, error) {
	rest, ok := strings.CutPrefix(id, "fake-gpu-")
	if !ok {
		return 0, fmt.Errorf("device id %q is not fake-gpu-N", id)
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 || rest != strconv.Itoa(n) {
		return 0, fmt.Errorf("device id %q is not fake-gpu-N", id)
	}
	return n, nil
}

func formatDcgm(
	count int,
	hostname, utilDefault, fbDefault string,
	assigned map[string]assign,
	lookup func(namespace, name string) (map[string]string, error),
) (string, error) {
	for id := range assigned {
		n, err := deviceIndex(id)
		if err != nil {
			return "", err
		}
		if n >= count {
			return "", fmt.Errorf("pod-resources has %s but FAKE_GPU_COUNT=%d", id, count)
		}
	}
	var utilLines []string
	var fbLines []string
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("fake-gpu-%d", i)
		util, fb := utilDefault, fbDefault
		extra := ""
		if a, ok := assigned[id]; ok {
			ann, err := lookup(a.namespace, a.name)
			if errors.Is(err, errPodGone) {
				// List still names a deleted pod. Drop pod labels.
			} else if err != nil {
				return "", err
			} else {
				util, err = override(utilDefault, ann, annGPUUtil)
				if err != nil {
					return "", err
				}
				fb, err = override(fbDefault, ann, annFBUsed)
				if err != nil {
					return "", err
				}
				extra = fmt.Sprintf(",namespace=%q,pod=%q,container=%q", a.namespace, a.name, a.container)
			}
		}
		base := fmt.Sprintf(
			`gpu=%q,UUID="GPU-fake-%d",device="nvidia%d",modelName=%q,Hostname=%q%s`,
			id, i, i, dcgmModelName, hostname, extra,
		)
		utilLines = append(utilLines, fmt.Sprintf("DCGM_FI_DEV_GPU_UTIL{%s} %s", base, util))
		fbLines = append(fbLines, fmt.Sprintf("DCGM_FI_DEV_FB_USED{%s} %s", base, fb))
	}
	var b strings.Builder
	b.WriteString("# TYPE DCGM_FI_DEV_GPU_UTIL gauge\n")
	for _, l := range utilLines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	b.WriteString("# TYPE DCGM_FI_DEV_FB_USED gauge\n")
	for _, l := range fbLines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func override(def string, ann map[string]string, key string) (string, error) {
	raw, ok := ann[key]
	if !ok {
		return def, nil
	}
	raw = strings.TrimSpace(raw)
	if err := finiteNumber(raw); err != nil {
		return "", fmt.Errorf("annotation %s=%q: %w", key, raw, err)
	}
	return raw, nil
}

func podAnnotations(namespace, name string) (map[string]string, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT unset")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount token: %w", err)
	}
	caPEM, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("serviceaccount ca.crt has no certificates")
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "kubernetes.default.svc",
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u := fmt.Sprintf(
		"https://%s:%s/api/v1/namespaces/%s/pods/%s",
		host, port, url.PathEscape(namespace), url.PathEscape(name),
	)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errPodGone
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get pod %s/%s: HTTP %s", namespace, name, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read pod %s/%s: %w", namespace, name, err)
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode pod %s/%s: %w", namespace, name, err)
	}
	if doc.Metadata.Annotations == nil {
		return map[string]string{}, nil
	}
	return doc.Metadata.Annotations, nil
}
