/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/daeipc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	externalPolicySocketEnv           = "DAE_EXTERNAL_POLICY_SOCKET"
	externalPolicyUIDEnv              = "DAE_EXTERNAL_POLICY_UID"
	externalPolicyConnectTimeout      = 30 * time.Second
	externalPolicyConnectMinDelay     = 50 * time.Millisecond
	externalPolicyConnectMaxDelay     = time.Second
	externalPolicyRegistrationTimeout = 10 * time.Second
	externalPolicyMetadataAttempts    = 3
)

var externalPolicyGeneration atomic.Uint64

type externalPolicySession struct {
	conn       *net.UnixConn
	generation uint64
}

// ExternalPolicyConfigured reports whether this process is configured to hand
// the datapath to an external policy engine. Keep environment parsing here so
// startup and reload code cannot drift from control-plane activation rules.
func ExternalPolicyConfigured() bool {
	return configuredExternalPolicySocket() != ""
}

func configuredExternalPolicySocket() string {
	return strings.TrimSpace(os.Getenv(externalPolicySocketEnv))
}

func (c *ControlPlane) openExternalPolicySession(listener *Listener) (*externalPolicySession, error) {
	if c == nil || c.externalPolicySocket == "" {
		return nil, fmt.Errorf("external policy socket is not configured")
	}
	if listener == nil {
		return nil, fmt.Errorf("nil listener")
	}

	conn, err := dialExternalPolicy(c.ctx, c.externalPolicySocket)
	if err != nil {
		return nil, err
	}
	closeConn := true
	defer func() {
		if closeConn {
			_ = conn.Close()
		}
	}()

	credentials, err := daeipc.PeerCredentials(conn)
	if err != nil {
		return nil, fmt.Errorf("authenticate external policy peer: %w", err)
	}
	if credentials.Uid != c.externalPolicyUID {
		return nil, fmt.Errorf("external policy peer uid %d does not match expected uid %d", credentials.Uid, c.externalPolicyUID)
	}

	listenerKinds, files, err := externalPolicyListenerFiles(listener)
	if err != nil {
		return nil, err
	}
	defer closeExternalPolicyFiles(files)

	generation := externalPolicyGeneration.Add(1)
	register := daeipc.NewMessage(daeipc.TypeRegister)
	register.Generation = generation
	register.TProxyPort = listener.port
	register.OutputMark = c.soMarkFromDae
	register.Listeners = listenerKinds
	if err := daeipc.Write(conn, register, files...); err != nil {
		return nil, fmt.Errorf("register external policy listeners: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(externalPolicyRegistrationTimeout)); err != nil {
		return nil, fmt.Errorf("set external policy registration deadline: %w", err)
	}
	ack, ackFiles, err := daeipc.Read(conn)
	closeExternalPolicyFiles(ackFiles)
	if clearErr := conn.SetDeadline(time.Time{}); clearErr != nil && err == nil {
		err = clearErr
	}
	if err != nil {
		return nil, fmt.Errorf("read external policy registration acknowledgement: %w", err)
	}
	if len(ackFiles) != 0 {
		return nil, fmt.Errorf("registration acknowledgement included %d unexpected file descriptors", len(ackFiles))
	}
	if ack.Type != daeipc.TypeRegisterAck {
		return nil, fmt.Errorf("unexpected external policy response %q", ack.Type)
	}
	if ack.Generation != generation {
		return nil, fmt.Errorf("external policy acknowledged generation %d, want %d", ack.Generation, generation)
	}
	if ack.Error != "" {
		return nil, fmt.Errorf("external policy rejected listener generation: %s", ack.Error)
	}

	closeConn = false
	return &externalPolicySession{conn: conn, generation: generation}, nil
}

func configuredExternalPolicyUID() (uint32, error) {
	rawUID := strings.TrimSpace(os.Getenv(externalPolicyUIDEnv))
	if rawUID == "" {
		return uint32(os.Geteuid()), nil
	}
	uid, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", externalPolicyUIDEnv, err)
	}
	return uint32(uid), nil
}

func dialExternalPolicy(parent context.Context, socketPath string) (*net.UnixConn, error) {
	if parent == nil {
		parent = context.Background()
	}
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return nil, fmt.Errorf("empty external policy socket path")
	}

	ctx, cancel := context.WithTimeout(parent, externalPolicyConnectTimeout)
	defer cancel()

	address := &net.UnixAddr{Name: socketPath, Net: "unixpacket"}
	delay := externalPolicyConnectMinDelay
	var lastErr error
	for {
		conn, err := net.DialUnix("unixpacket", nil, address)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, fmt.Errorf("connect external policy socket %q: %w", socketPath, lastErr)
		case <-timer.C:
		}
		if delay < externalPolicyConnectMaxDelay {
			delay *= 2
			if delay > externalPolicyConnectMaxDelay {
				delay = externalPolicyConnectMaxDelay
			}
		}
	}
}

func externalPolicyListenerFiles(listener *Listener) ([]string, []*os.File, error) {
	if listener == nil {
		return nil, nil, fmt.Errorf("nil listener")
	}
	var (
		kinds []string
		files []*os.File
	)
	fail := func(err error) ([]string, []*os.File, error) {
		closeExternalPolicyFiles(files)
		return nil, nil, err
	}

	if listener.tcp4Listener == nil || listener.tcp6Listener == nil || listener.packetConn == nil {
		return fail(fmt.Errorf("external policy requires TCP4, TCP6, and UDP listeners"))
	}

	tcp4File, err := dupTCPListenerFile(listener.tcp4Listener)
	if err != nil {
		return fail(fmt.Errorf("duplicate TCP4 listener: %w", err))
	}
	kinds = append(kinds, daeipc.ListenerTCP4)
	files = append(files, tcp4File)

	tcp6File, err := dupTCPListenerFile(listener.tcp6Listener)
	if err != nil {
		return fail(fmt.Errorf("duplicate TCP6 listener: %w", err))
	}
	kinds = append(kinds, daeipc.ListenerTCP6)
	files = append(files, tcp6File)

	udpFile, err := dupUDPPacketConnFile(listener.packetConn)
	if err != nil {
		return fail(fmt.Errorf("duplicate UDP listener: %w", err))
	}
	udpKind := daeipc.ListenerUDP4
	if address, ok := listener.packetConn.LocalAddr().(*net.UDPAddr); ok {
		if addr := address.AddrPort().Addr(); addr.Is6() && !addr.Is4In6() {
			udpKind = daeipc.ListenerUDP6
		}
	}
	kinds = append(kinds, udpKind)
	files = append(files, udpFile)
	return kinds, files, nil
}

func closeExternalPolicyFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (c *ControlPlane) serveExternalPolicySession(session *externalPolicySession) error {
	if c == nil || c.ctx == nil || session == nil || session.conn == nil {
		return fmt.Errorf("invalid external policy session")
	}

	conn := session.conn
	defer func() { _ = conn.Close() }()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-c.ctx.Done():
			_ = conn.Close()
		case <-closed:
		}
	}()

	for {
		message, files, err := daeipc.Read(conn)
		closeExternalPolicyFiles(files)
		if err != nil {
			if c.ctx.Err() != nil || stderrors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("external policy session disconnected: %w", err)
		}
		if len(files) != 0 {
			return fmt.Errorf("external policy message %q included %d unexpected file descriptors", message.Type, len(files))
		}

		switch message.Type {
		case daeipc.TypeLookup:
			response := c.externalPolicyLookupResponse(message, session.generation)
			if err := daeipc.Write(conn, response); err != nil {
				return fmt.Errorf("write external policy metadata response: %w", err)
			}
		case daeipc.TypePing:
			response := daeipc.NewMessage(daeipc.TypePong)
			response.RequestID = message.RequestID
			response.Generation = session.generation
			if err := daeipc.Write(conn, response); err != nil {
				return fmt.Errorf("write external policy pong: %w", err)
			}
		default:
			return fmt.Errorf("unsupported external policy message type %q", message.Type)
		}
	}
}

func (c *ControlPlane) externalPolicyLookupResponse(request daeipc.Message, generation uint64) daeipc.Message {
	response := daeipc.NewMessage(daeipc.TypeLookupResponse)
	response.RequestID = request.RequestID
	response.Generation = generation

	if request.Generation != generation {
		response.Error = fmt.Sprintf("generation mismatch: got %d, want %d", request.Generation, generation)
		return response
	}
	if request.RequestID == 0 {
		response.Error = "missing request_id"
		return response
	}
	var protocol uint8
	switch request.Network {
	case daeipc.NetworkTCP:
		protocol = consts.IPPROTO_TCP
	case daeipc.NetworkUDP:
		protocol = unix.IPPROTO_UDP
	default:
		response.Error = "unsupported network " + strconv.Quote(request.Network)
		return response
	}
	source, err := netip.ParseAddrPort(request.Source)
	if err != nil {
		response.Error = "invalid source: " + err.Error()
		return response
	}
	destination, err := netip.ParseAddrPort(request.Destination)
	if err != nil {
		response.Error = "invalid destination: " + err.Error()
		return response
	}
	source = common.ConvergeAddrPort(source)
	destination = common.ConvergeAddrPort(destination)
	if c == nil || c.core == nil {
		response.Error = "external policy control plane is unavailable"
		return response
	}
	lookupContext := c.ctx
	if lookupContext == nil {
		lookupContext = context.Background()
	}

	var routingResult *bpfRoutingResult
	if protocol == consts.IPPROTO_TCP {
		routingResult, err = retryRetrieveRoutingResult(lookupContext, func() (*bpfRoutingResult, error) {
			return c.core.RetrieveRoutingResult(source, destination, protocol)
		}, externalPolicyMetadataAttempts, tcpRoutingLookupRetryDelay)
	} else {
		routingResult, err = c.core.RetrieveRoutingResult(source, destination, protocol)
	}
	if err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			return response
		}
		response.Error = err.Error()
		return response
	}

	response.Found = true
	response.PID = routingResult.Pid
	response.ProcessName = ProcessName2String(routingResult.Pname[:])
	response.SourceMAC = externalPolicyMACString(routingResult.Mac)
	response.DSCP = routingResult.Dscp
	response.ProcessPath, response.UserID, response.HasUserID = externalPolicyProcessDetails(routingResult.Pid)
	return response
}

func externalPolicyMACString(mac [6]uint8) string {
	var nonzero bool
	for _, value := range mac {
		if value != 0 {
			nonzero = true
			break
		}
	}
	if !nonzero {
		return ""
	}
	return net.HardwareAddr(mac[:]).String()
}

func externalPolicyProcessDetails(pid uint32) (processPath string, userID int32, hasUserID bool) {
	if pid == 0 {
		return "", 0, false
	}
	procPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
	if path, err := os.Readlink(filepath.Join(procPath, "exe")); err == nil {
		processPath = strings.TrimSuffix(path, " (deleted)")
	}
	if info, err := os.Stat(procPath); err == nil {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid <= 1<<31-1 {
			userID = int32(stat.Uid)
			hasUserID = true
		}
	}
	return processPath, userID, hasUserID
}

func (c *ControlPlane) logExternalPolicyReady(session *externalPolicySession) {
	if c == nil || c.log == nil || session == nil {
		return
	}
	c.log.WithFields(logrus.Fields{
		"socket":     c.externalPolicySocket,
		"generation": session.generation,
		"mark":       fmt.Sprintf("%#x", c.soMarkFromDae),
		"peer_uid":   c.externalPolicyUID,
	}).Info("Transparent listeners handed to external policy engine")
}
