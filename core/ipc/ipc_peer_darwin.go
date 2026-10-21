//go:build darwin

package ipc

import (
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// socketMode permits connections from any local account, like on Linux:
// Accept enforces kernel-verified peer identity (LOCAL_PEERCRED) before
// admitting a peer, so the permission bits are not the boundary.
const socketMode = 0o666

// peerOf obtains UID and PID from the kernel via LOCAL_PEERCRED /
// LOCAL_PEERPID on the unix socket, never from client-supplied values.
// The UID is the verified part; the PID is best-effort diagnostics
// (LOCAL_PEERPID is documented as informational on macOS).
func peerOf(connection net.Conn) Peer {
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		return Peer{Detail: "not a unix connection"}
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return Peer{Detail: "the connection carries no kernel handle"}
	}
	var (
		credentials *unix.Xucred
		pid         int
		innerErr    error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, innerErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if innerErr == nil {
			// A missing PID must not cost the verified UID.
			pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return Peer{Detail: "the connection cannot be inspected"}
	}
	if innerErr != nil || credentials == nil {
		return Peer{Detail: "the peer credentials are not available"}
	}
	return Peer{
		UID:      int(credentials.Uid),
		PID:      pid,
		Verified: true,
		Detail:   "uid " + strconv.Itoa(int(credentials.Uid)) + " pid " + strconv.Itoa(pid),
	}
}
