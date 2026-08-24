// SPDX-License-Identifier: AGPL-3.0-only

// Package embedded constructs dae's Linux eBPF inbound in-process. It is the
// direct-import provider for traffic engines such as sing-box and Xray; no IPC
// protocol or dae daemon is involved.
package embedded

import (
	"context"
	"io"

	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/ebpfinbound"
	"github.com/sirupsen/logrus"
)

// Options uses standard-library types at the provider boundary. The logrus
// dependency remains an implementation detail of dae's current compatibility
// runtime and can disappear when the datapath is physically extracted.
type Options struct {
	Capture   ebpfinbound.CaptureConfig
	LogOutput io.Writer
	LogLevel  string
}

func New(ctx context.Context, options Options) (ebpfinbound.Runtime, error) {
	logger := logrus.New()
	if options.LogOutput != nil {
		logger.SetOutput(options.LogOutput)
	} else {
		logger.SetOutput(io.Discard)
	}
	if options.LogLevel != "" {
		level, err := logrus.ParseLevel(options.LogLevel)
		if err != nil {
			return nil, err
		}
		logger.SetLevel(level)
	}
	return control.NewCaptureRuntime(ctx, logger, options.Capture)
}
