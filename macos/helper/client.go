package main

// Control client for the sora-core daemon, speaking the daemon's
// default wire protocol.
//
// Why not gRPC: the daemon binary (core/cmd/sora-core) serves gRPC only
// when started with -legacy-control=false; its default — and therefore
// what service/darwin launches — is core/legacycontrol: JSON-RPC 2.0,
// one JSON object per line, over the same account-restricted unix
// socket (core/ipc), where every method payload is the protojson of the
// sora.core.v1 (contract 1.7) request and the result is the protojson
// of the response as a JSON string. That is the exact protocol the
// shipping .NET client uses (legacy/Control/CoreConnection.cs) and the
// one core/legacycontrol's own tests drive from Go (jrpc2 client over
// channel.Line). Reusing it means the macOS helper needs no new daemon
// mode, no second protocol implementation, and no Swift gRPC stack.
//
// Why not a hand-rolled socket protocol: core/ipc exposes only the
// transport (Listen/Dial, peer checks); there is no simpler message
// protocol above it — above the socket there is exactly this JSON-RPC
// contract or gRPC, nothing else.

import (
	"context"
	"fmt"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/ipc"
)

// clientVersion is the contract this helper speaks: sora.core.v1 1.7,
// the version core/cmd/sora-core serves (Version in its main.go).
var clientVersion = &corev1.ApiVersion{Major: 1, Minor: 7, MinSupportedMinor: 1}

// rpcParams mirrors legacycontrol.parameters on the server side.
type rpcParams struct {
	Payload  string `json:"payload"`
	StreamID string `json:"streamId,omitempty"`
}

// client is one connection to the daemon. The control token obtained in
// Handshake lives only in this process's memory; it is never written
// to disk by the helper.
type client struct {
	rpc     *jrpc2.Client
	version *corev1.ApiVersion
	token   []byte
}

// dial connects to the daemon socket and performs the Handshake, which
// negotiates the contract version and issues the control token to
// admitted peers (the socket's peer allow-list is the boundary; on
// darwin the peer is kernel-verified via LOCAL_PEERCRED).
func dial(ctx context.Context, socket string) (*client, error) {
	conn, err := ipc.Dial(ctx, socket)
	if err != nil {
		return nil, fmt.Errorf("sora-ctl: the core service is not reachable at %s: %s", socket, errorText(err))
	}
	c := &client{rpc: jrpc2.NewClient(channel.Line(conn, conn), nil)}
	resp := &corev1.HandshakeResponse{}
	if err := c.call(ctx, "Handshake", &corev1.HandshakeRequest{ClientVersion: clientVersion}, resp); err != nil {
		_ = c.rpc.Close()
		return nil, err
	}
	if resp.GetError() != nil {
		_ = c.rpc.Close()
		return nil, refusedError("handshake", resp.GetError())
	}
	if len(resp.GetControlAuthenticator()) == 0 {
		_ = c.rpc.Close()
		return nil, fmt.Errorf("sora-ctl: handshake returned no control token")
	}
	c.version = resp.GetNegotiatedVersion()
	c.token = resp.GetControlAuthenticator()
	return c, nil
}

func (c *client) close() { _ = c.rpc.Close() }

// call performs one unary method: protojson in, protojson out, exactly
// as legacycontrol's handler expects.
func (c *client) call(ctx context.Context, method string, request, response proto.Message) error {
	payload, err := protojson.Marshal(request)
	if err != nil {
		return err
	}
	var result string
	if err := c.rpc.CallResult(ctx, method, rpcParams{Payload: string(payload)}, &result); err != nil {
		return fmt.Errorf("sora-ctl: %s: %s", method, errorText(err))
	}
	if err := protojson.Unmarshal([]byte(result), response); err != nil {
		return fmt.Errorf("sora-ctl: %s: unreadable response: %s", method, errorText(err))
	}
	return nil
}
