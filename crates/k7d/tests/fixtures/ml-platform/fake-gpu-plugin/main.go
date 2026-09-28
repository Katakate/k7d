// Fake kubelet device plugin that advertises nvidia.com/gpu.
// Count comes from FAKE_GPU_COUNT (default 2). Unset keeps the
// JobSet Capacity=2 contract; a set-but-invalid value
// fails loud instead of silently falling back.
//
// Allocate sets NVIDIA_VISIBLE_DEVICES to the kubelet-assigned
// fake-gpu-N IDs. `-list-pod-resources` dumps the kubelet
// pod-resources API as JSON (same IDs the container should see).
// `-render-dcgm` writes one DCGM-shaped series per fake-gpu-N.
// Node identity (product, count, present, topology block/rack) is
// applied before registration. See applyNodeIdentity in label.go.
//
// Fixture only: no NVML, no /dev/nvidia*, no CUDA.
// Socket dir comes from PLUGIN_SOCK_DIR so the DaemonSet can point at
// k3s' kubelet path instead of stock /var/lib/kubelet/device-plugins/.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
)

const (
	resourceName       = "nvidia.com/gpu"
	defaultDeviceCount = 2
	socketName         = "nvidia-gpu.sock"
)

func fakeGpuCount() int {
	raw := strings.TrimSpace(os.Getenv("FAKE_GPU_COUNT"))
	if raw == "" {
		return defaultDeviceCount
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		log.Fatalf("FAKE_GPU_COUNT=%q: want a positive integer", raw)
	}
	return n
}

func resolveSockDir() string {
	env := os.Getenv("PLUGIN_SOCK_DIR")
	candidates := make([]string, 0, 3)
	if env != "" {
		candidates = append(candidates, env)
	}
	for _, d := range []string{
		"/var/lib/kubelet/device-plugins",
		"/var/lib/rancher/k3s/agent/kubelet/device-plugins",
	} {
		if d != env {
			candidates = append(candidates, d)
		}
	}
	var missing []string
	for _, d := range candidates {
		sock := filepath.Join(d, "kubelet.sock")
		if _, err := os.Stat(sock); err == nil {
			log.Printf("using kubelet.sock at %s", sock)
			return d
		}
		missing = append(missing, sock)
	}
	log.Fatalf("kubelet.sock not found; tried %v", missing)
	return ""
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-list-pod-resources":
			listPodResources()
			return
		case "-render-dcgm":
			renderDcgm()
			return
		default:
			log.Fatalf("unknown arg %q", os.Args[1])
		}
	}

	sockDir := resolveSockDir()
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", sockDir, err)
	}

	pluginSock := filepath.Join(sockDir, socketName)
	kubeletSock := filepath.Join(sockDir, "kubelet.sock")
	_ = os.Remove(pluginSock)

	lis, err := net.Listen("unix", pluginSock)
	if err != nil {
		log.Fatalf("listen %s: %v", pluginSock, err)
	}
	if err := os.Chmod(pluginSock, 0o666); err != nil {
		log.Fatalf("chmod %s: %v", pluginSock, err)
	}

	count := fakeGpuCount()
	if err := applyNodeIdentity(count); err != nil {
		log.Fatalf("apply node identity: %v", err)
	}
	srv := grpc.NewServer()
	pluginapi.RegisterDevicePluginServer(srv, &plugin{count: count})
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := register(ctx, kubeletSock); err != nil {
		log.Fatalf("register with kubelet at %s: %v", kubeletSock, err)
	}
	log.Printf("registered %s count=%d via %s", resourceName, count, sockDir)

	<-ctx.Done()
	srv.GracefulStop()
	_ = os.Remove(pluginSock)
}

func register(ctx context.Context, kubeletSock string) error {
	var last error
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(kubeletSock); err != nil {
			last = fmt.Errorf("kubelet.sock missing at %s: %w", kubeletSock, err)
			time.Sleep(time.Second)
			continue
		}
		conn, err := grpc.NewClient(
			"passthrough:///kubelet",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", kubeletSock)
			}),
		)
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		_, err = pluginapi.NewRegistrationClient(conn).Register(ctx, &pluginapi.RegisterRequest{
			Version:      pluginapi.Version,
			Endpoint:     socketName,
			ResourceName: resourceName,
		})
		_ = conn.Close()
		if err == nil {
			return nil
		}
		last = err
		log.Printf("register attempt %d: %v", i+1, err)
		time.Sleep(time.Second)
	}
	return last
}

type plugin struct {
	pluginapi.UnimplementedDevicePluginServer
	count int
}

func devices(n int) []*pluginapi.Device {
	out := make([]*pluginapi.Device, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &pluginapi.Device{
			ID:     fmt.Sprintf("fake-gpu-%d", i),
			Health: pluginapi.Healthy,
		})
	}
	return out
}

func (p *plugin) GetDevicePluginOptions(context.Context, *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

func (p *plugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	if err := stream.Send(&pluginapi.ListAndWatchResponse{Devices: devices(p.count)}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (p *plugin) Allocate(_ context.Context, req *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := &pluginapi.AllocateResponse{}
	for _, cr := range req.ContainerRequests {
		resp.ContainerResponses = append(resp.ContainerResponses, &pluginapi.ContainerAllocateResponse{
			Envs: map[string]string{
				"NVIDIA_VISIBLE_DEVICES": strings.Join(cr.DevicesIDs, ","),
			},
		})
	}
	return resp, nil
}

func (p *plugin) GetPreferredAllocation(_ context.Context, req *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	resp := &pluginapi.PreferredAllocationResponse{}
	for _, cr := range req.ContainerRequests {
		want := int(cr.AllocationSize)
		ids := cr.AvailableDeviceIDs
		if want > len(ids) {
			want = len(ids)
		}
		resp.ContainerResponses = append(resp.ContainerResponses, &pluginapi.ContainerPreferredAllocationResponse{
			DeviceIDs: ids[:want],
		})
	}
	return resp, nil
}

func (p *plugin) PreStartContainer(context.Context, *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

type podResourceRow struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Container string   `json:"container"`
	Resource  string   `json:"resource"`
	IDs       []string `json:"ids"`
}

func resolvePodResourcesSock() string {
	var missing []string
	for _, sock := range []string{
		"/var/lib/kubelet/pod-resources/kubelet.sock",
		"/var/lib/rancher/k3s/agent/kubelet/pod-resources/kubelet.sock",
		"/var/lib/rancher/k3s/agent/pod-resources/kubelet.sock",
	} {
		if _, err := os.Stat(sock); err == nil {
			return sock
		}
		missing = append(missing, sock)
	}
	log.Fatalf("pod-resources kubelet.sock not found; tried %v", missing)
	return ""
}

func listPodResources() {
	rows, err := fetchPodResources()
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(rows); err != nil {
		log.Fatalf("encode pod-resources: %v", err)
	}
}

func fetchPodResources() ([]podResourceRow, error) {
	sock := resolvePodResourcesSock()
	conn, err := grpc.NewClient(
		"passthrough:///podresources",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", sock, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := podresourcesapi.NewPodResourcesListerClient(conn).List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		return nil, fmt.Errorf("List pod-resources via %s: %w", sock, err)
	}

	rows := make([]podResourceRow, 0)
	// proto field is pod_resources, not pods (k8s.io/kubelet v0.32).
	for _, pod := range resp.GetPodResources() {
		for _, c := range pod.GetContainers() {
			for _, d := range c.GetDevices() {
				rows = append(rows, podResourceRow{
					Namespace: pod.GetNamespace(),
					Name:      pod.GetName(),
					Container: c.GetName(),
					Resource:  d.GetResourceName(),
					IDs:       append([]string(nil), d.GetDeviceIds()...),
				})
			}
		}
	}
	return rows, nil
}
