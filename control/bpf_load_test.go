//go:build linux && dae_bpf_tests

package control

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func loadBpfObjectsWithConstants(obj interface{}, opts *ebpf.CollectionOptions, constants map[string]interface{}) error {
	return loadBpfObjectsWithConstantsAndCustomizer(obj, opts, constants, nil)
}

func TestLoadMainBPFObjects(t *testing.T) {
	testLoadMainBPFObjects(t, 0)
}

func TestLoadMainBPFObjectsWithDaeSocketMark(t *testing.T) {
	testLoadMainBPFObjects(t, 0x73ae)
}

func testLoadMainBPFObjects(t *testing.T, daeSocketMark uint32) {
	t.Helper()

	var obj bpfObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	}

	constants := map[string]interface{}{
		"PARAM": bpfDaeParam{DaeSocketMark: daeSocketMark},
	}

	if err := loadBpfObjectsWithConstantsAndCustomizer(&obj, opts, constants, disableAllPinnedMapsForTests); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load main bpf objects: verifier:\n%+v", ve)
		}
		t.Fatalf("load main bpf objects: %+v", err)
	}
	defer func() { _ = obj.Close() }()
}
