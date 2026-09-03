// Fake kubelet device plugin that advertises nvidia.com/gpu count=2.
//
// Fixture only : no NVML, no /dev/nvidia*, no CUDA.
// Socket dir comes from PLUGIN_SOCK_DIR so the DaemonSet can point at
// k3s' kubelet path instead of stock /var/lib/kubelet/device-plugins/.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	resourceName = "nvidia.com/gpu"
	deviceCount  = 2
	socketName   = "nvidia-gpu.sock"
)

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

	srv := grpc.NewServer()
	pluginapi.RegisterDevicePluginServer(srv, &plugin{})
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
	log.Printf("registered %s count=%d via %s", resourceName, deviceCount, sockDir)

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
}

func devices() []*pluginapi.Device {
	out := make([]*pluginapi.Device, 0, deviceCount)
	for i := 0; i < deviceCount; i++ {
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
	if err := stream.Send(&pluginapi.ListAndWatchResponse{Devices: devices()}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func (p *plugin) Allocate(_ context.Context, req *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := &pluginapi.AllocateResponse{}
	for range req.ContainerRequests {
		resp.ContainerResponses = append(resp.ContainerResponses, &pluginapi.ContainerAllocateResponse{})
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
