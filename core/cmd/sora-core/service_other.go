//go:build !windows

package main

import "errors"

// runService reports that SCM did not start the core. Linux runs it as a
// process under systemd.
func runService([]string) (bool, error) { return false, nil }

var errNotWindows = errors.New("registering a service is Windows only; Linux uses the systemd unit, macOS the LaunchDaemon")

func installService([]string) error { return errNotWindows }

func uninstallService() error { return errNotWindows }
