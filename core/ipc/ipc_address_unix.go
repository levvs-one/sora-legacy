//go:build !windows && !darwin

package ipc

// ListenAddress is the platform's core endpoint address.
func ListenAddress() string { return "/run/sora/core.sock" }
