package ipc_test

// Mirror pin for the hand-spelled endpoint constants (final pass 3).
//
// The Windows named pipe and the Windows service name are the rendezvous
// between the Go core and the C# client: each side spells them by hand,
// in a different language, and a one-character drift on either side is
// not a compile error anywhere — the client simply never finds the
// core (or, worse, trusts the wrong service). The same spellings also
// live in the diagnostics event-log query and in the interop test
// harness. This test reads every spelling in the tree and requires
// them all to be the same strings. The Go spellings sit in
// windows-only files, so they are read as text here; the test itself
// is platform-independent.

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func mirrorRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "core", "ipc", "ipc_windows.go")); err != nil {
		t.Fatalf("repository root not found from the ipc package: %v", err)
	}
	return root
}

func mirrorRead(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func mirrorExtract(t *testing.T, root, rel, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(mirrorRead(t, root, rel))
	if m == nil {
		t.Fatalf("%s: pattern %q not found", rel, pattern)
	}
	return m[1]
}

func TestMirrorEndpointConstants(t *testing.T) {
	root := mirrorRepoRoot(t)

	// The pipe: the Go core owns the full \\.\pipe\ name; the C#
	// side spells the bare pipe name (it passes "." as the server).
	goPipe := mirrorExtract(t, root, "core/ipc/ipc_windows.go", "const pipeName = `([^`]+)`")
	const wantPipeSuffix = `sora-legacy-core-v1`
	if goPipe != `\\.\pipe\`+wantPipeSuffix {
		t.Errorf("Go pipeName = %q, want %q", goPipe, `\\.\pipe\`+wantPipeSuffix)
	}
	csPipe := mirrorExtract(t, root, "legacy/Control/CoreService.cs",
		`NamedPipeClientStream\("\.", "([^"]+)"`)
	if csPipe != wantPipeSuffix {
		t.Errorf("C# client pipe = %q, Go spells %q", csPipe, goPipe)
	}
	harnessPipe := mirrorExtract(t, root, "legacy/tests/ServiceInterop/Program.cs",
		`NamedPipeServerStream\("([^"]+)"`)
	if harnessPipe != wantPipeSuffix {
		t.Errorf("interop harness pipe = %q, Go spells %q", harnessPipe, goPipe)
	}

	// The service: the Go core registers itself under this name; the
	// C# client verifies the pipe's owner process against the SCM
	// entry of the same name, and the diagnostics collector queries
	// the event log by the same provider name.
	goService := mirrorExtract(t, root, "core/cmd/sora-core/service_windows.go",
		`const serviceName = "([^"]+)"`)
	csService := mirrorExtract(t, root, "legacy/Control/CoreService.cs",
		`OpenService\(manager, "([^"]+)"`)
	if csService != goService {
		t.Errorf("C# client verifies service %q, the core registers %q", csService, goService)
	}
	provider := mirrorExtract(t, root, "core/diagnostics/events_windows.go",
		`Provider\[@Name='([^']+)'\]`)
	if provider != goService {
		t.Errorf("diagnostics event provider = %q, the core registers service %q", provider, goService)
	}
	if goService != "SoraLegacyCore" {
		t.Errorf("service name = %q, want the recorded SoraLegacyCore", goService)
	}
}
