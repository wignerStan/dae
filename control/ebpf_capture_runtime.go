// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/ebpfinbound"
	"github.com/sirupsen/logrus"
)

type captureRuntime struct {
	inner ebpfinbound.Runtime
	netns *DaeNetns
	once  sync.Once
	err   error
}

var _ ebpfinbound.Runtime = (*captureRuntime)(nil)

// NewCaptureRuntime creates dae's eBPF datapath in capture-only mode.
// dae does not become the route, DNS, sniffing, or outbound authority.
func NewCaptureRuntime(ctx context.Context, log *logrus.Logger, raw ebpfinbound.CaptureConfig) (ebpfinbound.Runtime, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	capture := raw.WithDefaults()
	if err := capture.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = logrus.New()
	}

	InitDaeNetns(log)
	netns := GetDaeNetns()
	if netns == nil {
		return nil, errors.New("initialize dae network namespace")
	}
	if err := netns.Setup(); err != nil {
		return nil, fmt.Errorf("setup dae network namespace: %w", err)
	}

	mark := capture.OutputMark
	global := &config.Global{
		TproxyPort:                capture.TProxyPort,
		TproxyPortProtect:         true,
		SoMarkFromDae:             mark,
		SoMarkFromDaeSet:          mark != 0,
		LogLevel:                  "info",
		TcpCheckUrl:               []string{"1.1.1.1"},
		TcpCheckHttpMethod:        "HEAD",
		UdpCheckDns:               []string{"8.8.8.8:53"},
		CheckInterval:             30 * time.Second,
		LanInterface:              append([]string(nil), capture.LANInterfaces...),
		WanInterface:              append([]string(nil), capture.WANInterfaces...),
		DialMode:                  "ip",
		DisableWaitingNetwork:     true,
		DisableTHP:                true,
		AutoConfigKernelParameter: capture.AutoConfigureKernel,
		SniffingTimeout:           30 * time.Millisecond,
		TlsImplementation:         "tls",
		UtlsImitate:               "chrome_auto",
		BootstrapResolver:         "8.8.8.8:53",
		FallbackResolver:          "8.8.8.8:53",
		UDPHopInterval:            30 * time.Second,
		BpfConnStateMapSize:       capture.ConnectionStateMapEntries,
	}
	routingConfig := &config.Routing{Fallback: config.FunctionOrString("direct")}
	dnsConfig := &config.Dns{}

	plane, err := newControlPlaneWithContextOptions(
		ctx, log, nil, nil, map[string][]string{}, nil,
		routingConfig, global, dnsConfig, nil,
		controlPlaneBuildOptions{
			delayDatapathCommit:   true,
			delayDNSListenerStart: true,
			externalPolicy:        true,
		},
	)
	if err != nil {
		_ = netns.Close()
		return nil, fmt.Errorf("build capture-only control plane: %w", err)
	}
	return &captureRuntime{inner: plane.EBPFInbound(), netns: netns}, nil
}

func (r *captureRuntime) OpenGeneration(ctx context.Context, port uint16) (ebpfinbound.Generation, error) {
	if r == nil || r.inner == nil || r.netns == nil {
		return nil, errors.New("capture runtime is closed")
	}
	var generation ebpfinbound.Generation
	err := r.netns.WithRequired("open eBPF inbound generation", func() error {
		var err error
		generation, err = r.inner.OpenGeneration(ctx, port)
		return err
	})
	return generation, err
}

func (r *captureRuntime) CloneGeneration(ctx context.Context, generation ebpfinbound.Generation) (ebpfinbound.Generation, error) {
	if r == nil || r.inner == nil {
		return nil, errors.New("capture runtime is closed")
	}
	return r.inner.CloneGeneration(ctx, generation)
}

func (r *captureRuntime) CommitGeneration(ctx context.Context, generation ebpfinbound.Generation) error {
	if r == nil || r.inner == nil {
		return errors.New("capture runtime is closed")
	}
	return r.inner.CommitGeneration(ctx, generation)
}

func (r *captureRuntime) LookupMetadata(ctx context.Context, flow ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) {
	if r == nil || r.inner == nil {
		return ebpfinbound.Metadata{}, false, errors.New("capture runtime is closed")
	}
	return r.inner.LookupMetadata(ctx, flow)
}

func (r *captureRuntime) OutputMark() uint32 {
	if r == nil || r.inner == nil {
		return 0
	}
	return r.inner.OutputMark()
}

func (r *captureRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		var errs []error
		if r.inner != nil {
			if err := r.inner.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if r.netns != nil {
			if err := r.netns.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		r.inner = nil
		r.netns = nil
		r.err = errors.Join(errs...)
	})
	return r.err
}
