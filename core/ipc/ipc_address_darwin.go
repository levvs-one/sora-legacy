//go:build darwin

package ipc

// ListenAddress is the platform's core endpoint address. macOS has no
// writable /run (the root filesystem is read-only since 10.15); /var/run
// is the canonical runtime directory, a symlink to /private/var/run,
// world-traversable and writable by the root daemon.
func ListenAddress() string { return "/var/run/sora/core.sock" }
