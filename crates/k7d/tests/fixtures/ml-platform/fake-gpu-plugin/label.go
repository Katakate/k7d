package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Node labels the fake plugin stamps so a node looks like a GPU machine.
// Product / block / rack are configurable. Count follows FAKE_GPU_COUNT.
// kubernetes.io/hostname is already set by kubelet; Topology uses it as
// the finest level and this plugin does not rewrite it.
const (
	labelProduct = "nvidia.com/gpu.product"
	labelCount   = "nvidia.com/gpu.count"
	labelPresent = "nvidia.com/gpu.present"
	labelBlock   = "k7d.katakate.org/topology-block"
	labelRack    = "k7d.katakate.org/topology-rack"

	defaultProduct = "Fake-A100"
	defaultBlock   = "block-0"
	defaultRack    = "rack-0"

	identityConfigMap = "fake-gpu-identity"

	saToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCA    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNS    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// fatalErr stops the retry loop. Connection errors and RBAC lag retry.
type fatalErr struct{ error }

func (e fatalErr) Unwrap() error { return e.error }

type identity struct {
	product string
	block   string
	rack    string
}

// applyNodeIdentity labels this pod's node, then returns. Registration
// happens only after the labels stick, so Capacity implies identity.
func applyNodeIdentity(count int) error {
	if count < 1 {
		return fatalErr{fmt.Errorf("gpu count %d", count)}
	}
	node := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if node == "" {
		return fatalErr{fmt.Errorf("NODE_NAME is empty")}
	}
	client, base, err := kubeClient()
	if err != nil {
		return fatalErr{err}
	}
	var last error
	for i := 0; i < 45; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := labelOnce(ctx, client, base, node, count)
		cancel()
		if err == nil {
			return nil
		}
		var fatal fatalErr
		if errors.As(err, &fatal) {
			return err
		}
		last = err
		log.Printf("node identity attempt %d: %v", i+1, err)
		time.Sleep(time.Second)
	}
	return fmt.Errorf("after 45 attempts: %w", last)
}

func kubeClient() (*http.Client, string, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, "", fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT is empty")
	}
	caPEM, err := os.ReadFile(saCA)
	if err != nil {
		return nil, "", fmt.Errorf("read serviceaccount CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", fmt.Errorf("serviceaccount CA has no certificates")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return client, "https://" + host + ":" + port, nil
}

func labelOnce(ctx context.Context, client *http.Client, base, node string, count int) error {
	ns, err := os.ReadFile(saNS)
	if err != nil {
		return fmt.Errorf("read serviceaccount namespace: %w", err)
	}
	namespace := strings.TrimSpace(string(ns))
	if namespace == "" {
		return fatalErr{fmt.Errorf("serviceaccount namespace is empty")}
	}
	id, err := resolveIdentity(ctx, client, base, namespace, node)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"labels": map[string]string{
				labelProduct: id.product,
				labelCount:   fmt.Sprintf("%d", count),
				labelPresent: "true",
				labelBlock:   id.block,
				labelRack:    id.rack,
			},
		},
	})
	if err != nil {
		return fatalErr{err}
	}
	url := base + "/api/v1/nodes/" + node
	status, resp, err := kubeDo(ctx, client, http.MethodPatch, url, "application/merge-patch+json", body)
	if err != nil {
		return err
	}
	if status == http.StatusOK {
		log.Printf(
			"labeled node %s product=%s count=%d block=%s rack=%s",
			node, id.product, count, id.block, id.rack,
		)
		return nil
	}
	err = fmt.Errorf("patch node %s: HTTP %d: %s", node, status, strings.TrimSpace(string(resp)))
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		return fatalErr{err}
	}
	return err
}

// resolveIdentity uses the fake-gpu-identity ConfigMap when it exists
// (every node must have a line). A missing ConfigMap keeps the env
// defaults so a homogeneous pool does not need one.
func resolveIdentity(ctx context.Context, client *http.Client, base, namespace, node string) (identity, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", base, namespace, identityConfigMap)
	status, resp, err := kubeDo(ctx, client, http.MethodGet, url, "", nil)
	if err != nil {
		return identity{}, err
	}
	if status == http.StatusNotFound {
		return identityFromEnv()
	}
	if status != http.StatusOK {
		return identity{}, fmt.Errorf("get configmap %s: HTTP %d: %s", identityConfigMap, status, strings.TrimSpace(string(resp)))
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(resp, &cm); err != nil {
		return identity{}, fatalErr{fmt.Errorf("configmap %s: %w", identityConfigMap, err)}
	}
	line, ok := cm.Data[node]
	if !ok {
		return identity{}, fatalErr{fmt.Errorf("configmap %s has no entry for node %s", identityConfigMap, node)}
	}
	return parseIdentityLine(line)
}

func identityFromEnv() (identity, error) {
	product, err := envOrDefault("FAKE_GPU_PRODUCT", defaultProduct)
	if err != nil {
		return identity{}, err
	}
	block, err := envOrDefault("FAKE_GPU_TOPOLOGY_BLOCK", defaultBlock)
	if err != nil {
		return identity{}, err
	}
	rack, err := envOrDefault("FAKE_GPU_TOPOLOGY_RACK", defaultRack)
	if err != nil {
		return identity{}, err
	}
	return identity{product: product, block: block, rack: rack}, nil
}

func envOrDefault(key, fallback string) (string, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		if err := validLabelValue(fallback); err != nil {
			return "", fatalErr{fmt.Errorf("%s default: %w", key, err)}
		}
		return fallback, nil
	}
	v := strings.TrimSpace(raw)
	if err := validLabelValue(v); err != nil {
		return "", fatalErr{fmt.Errorf("%s=%q: %w", key, raw, err)}
	}
	return v, nil
}

func parseIdentityLine(line string) (identity, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return identity{}, fatalErr{fmt.Errorf("empty identity")}
	}
	got := map[string]string{}
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return identity{}, fatalErr{fmt.Errorf("identity %q: want key=value", line)}
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if _, dup := got[k]; dup {
			return identity{}, fatalErr{fmt.Errorf("identity %q: duplicate %s", line, k)}
		}
		got[k] = v
	}
	for _, k := range []string{"product", "block", "rack"} {
		if err := validLabelValue(got[k]); err != nil {
			return identity{}, fatalErr{fmt.Errorf("identity %q: %s: %w", line, k, err)}
		}
	}
	if len(got) != 3 {
		return identity{}, fatalErr{fmt.Errorf("identity %q: only product, block, rack are allowed", line)}
	}
	return identity{product: got["product"], block: got["block"], rack: got["rack"]}, nil
}

func validLabelValue(v string) error {
	if len(v) == 0 || len(v) > 63 {
		return fmt.Errorf("label value %q must be 1-63 characters", v)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		alnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if i == 0 || i == len(v)-1 {
			if !alnum {
				return fmt.Errorf("label value %q must start and end with an alphanumeric", v)
			}
			continue
		}
		if !alnum && c != '-' && c != '_' && c != '.' {
			return fmt.Errorf("label value %q contains an invalid character", v)
		}
	}
	return nil
}

func kubeDo(ctx context.Context, client *http.Client, method, url, contentType string, body []byte) (int, []byte, error) {
	token, err := os.ReadFile(saToken)
	if err != nil {
		return 0, nil, fmt.Errorf("read serviceaccount token: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, nil, fatalErr{err}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}
