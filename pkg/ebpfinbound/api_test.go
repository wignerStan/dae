// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"net/netip"
	"testing"
)

func TestFlowValidate(t *testing.T) {
	validSource := netip.MustParseAddrPort("192.0.2.10:12345")
	validDestination := netip.MustParseAddrPort("[2001:db8::10]:443")

	tests := []struct {
		name    string
		flow    Flow
		wantErr bool
	}{
		{
			name: "tcp",
			flow: Flow{
				Network:     NetworkTCP,
				Source:      validSource,
				Destination: validDestination,
			},
		},
		{
			name: "udp",
			flow: Flow{
				Network:     NetworkUDP,
				Source:      validSource,
				Destination: validDestination,
			},
		},
		{
			name: "unsupported network",
			flow: Flow{
				Network:     Network("icmp"),
				Source:      validSource,
				Destination: validDestination,
			},
			wantErr: true,
		},
		{
			name: "invalid source",
			flow: Flow{
				Network:     NetworkTCP,
				Destination: validDestination,
			},
			wantErr: true,
		},
		{
			name: "invalid destination",
			flow: Flow{
				Network: NetworkUDP,
				Source:  validSource,
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.flow.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
