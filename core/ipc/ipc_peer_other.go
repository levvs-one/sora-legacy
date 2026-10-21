//go:build !windows && !linux && !darwin

package ipc

import "net"

// socketMode restricts access to the service group when peer identity cannot be
// verified.
const socketMode = 0o660

// peerOf leaves Verified false on platforms without a kernel peer-credential
// mechanism wired up here (darwin has one: see ipc_peer_darwin.go). Socket
// permissions and the control token enforce access.
func peerOf(net.Conn) Peer {
	return Peer{Verified: false, Detail: "the permission on the socket is the boundary"}
}
