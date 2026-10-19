package supervise

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/levvs-one/sora-client/core/engine"
)

// Binary is one engine build on disk that has been probed successfully.
type Binary struct {
	Kind      engine.Kind
	Path      string
	Version   engine.Version
	Goos      string
	Goarch    string
	BuildTags []string
}

// Prober describes how to recognize one engine binary.
type Prober struct {
	Kind engine.Kind
	// Name is the executable name without extension, for example
	// "sing-box".
	Name string
	// EnvVar overrides the discovered binary path. It is read only when
	// AllowEnv is set: the operator explicitly opts into trusting an
	// environment-provided binary. The binary is still probed, but its
	// digest is not checked against the shipped manifest.
	EnvVar string
	// AllowEnv honors the EnvVar override. Keep it false unless the
	// operator passes --allow-env-bin: an inherited environment variable
	// would otherwise let any process able to influence the core's
	// environment substitute an arbitrary executable.
	AllowEnv bool
	// Args make the binary print its version, for example ["version"].
	Args []string
	// Pattern matches the first line of the version output. Group 1 is the
	// version; optional groups 2 and 3 are GOOS and GOARCH.
	Pattern *regexp.Regexp
}

// Probe runs version arguments and verifies the binary's identity before use.
func (pr Prober) Probe(ctx context.Context, path string) (Binary, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, pr.Args...) //nolint:gosec // path is a discovery candidate and the arguments are literals
	HideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return Binary{}, fmt.Errorf("%s: probe failed: %w: %s", pr.Kind, err, strings.TrimSpace(out.String()))
	}
	first, _, _ := strings.Cut(strings.TrimSpace(out.String()), "\n")
	match := pr.Pattern.FindStringSubmatch(strings.TrimSpace(first))
	if match == nil {
		return Binary{}, fmt.Errorf("%s: unexpected version output %q", pr.Kind, first)
	}
	version, err := engine.ParseVersion(match[1])
	if err != nil {
		return Binary{}, err
	}
	b := Binary{Kind: pr.Kind, Path: path, Version: version, Goos: runtime.GOOS, Goarch: runtime.GOARCH}
	for _, line := range strings.Split(out.String(), "\n") {
		if tags, ok := strings.CutPrefix(strings.TrimSpace(line), "Tags:"); ok {
			b.BuildTags = strings.Split(strings.TrimSpace(tags), ",")
		}
	}
	if len(match) > 3 && match[2] != "" && match[3] != "" {
		b.Goos, b.Goarch = match[2], match[3]
	}
	return b, nil
}

// digestManifestName is the SHA-256 manifest written next to shipped engine
// binaries by packaging/engines/fetch.sh. Discover verifies enginesDir
// candidates against it when present.
const digestManifestName = "SHA256SUMS"

// Discover checks the environment override (only when the prober allows it)
// and then the engines directory. It deliberately does not fall back to PATH:
// a PATH-planted binary with a plausible "version" output is trivial to forge,
// and executing it would run attacker code with the core's privileges.
// Digests of enginesDir candidates are verified against the shipped manifest
// when the manifest exists; installations without a manifest (manual or
// development layouts) are accepted as before. Discover does not download;
// fetch.sh ships engines and records their digests.
func (pr Prober) Discover(ctx context.Context, enginesDir string) (Binary, error) {
	var candidates []string
	if pr.AllowEnv {
		if fromEnv := os.Getenv(pr.EnvVar); pr.EnvVar != "" && fromEnv != "" {
			candidates = append(candidates, fromEnv)
		}
	}
	file := pr.Name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	var digests map[string]string
	if enginesDir != "" {
		candidates = append(candidates, filepath.Join(enginesDir, file))
		// A missing manifest only means a non-shipped layout; verification
		// is skipped rather than failing the whole discovery.
		digests, _ = LoadDigests(enginesDir)
	}
	lastErr := errors.New("no candidate")
	for _, candidate := range candidates {
		info, err := os.Stat(candidate) //nolint:gosec // candidates are the Sora engines dir or an operator-set env var
		if err != nil || info.IsDir() {
			lastErr = fmt.Errorf("%s is not a file", candidate)
			continue
		}
		if digests != nil {
			expected, ok := digests[filepath.Base(candidate)]
			if !ok {
				lastErr = fmt.Errorf("%s: not listed in %s", candidate, digestManifestName)
				continue
			}
			raw, err := os.ReadFile(candidate)
			if err != nil {
				lastErr = fmt.Errorf("%s: read binary: %w", candidate, err)
				continue
			}
			sum := sha256.Sum256(raw)
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(strings.TrimSpace(expected)))) != 1 {
				lastErr = fmt.Errorf("%s: digest mismatch: got %s", candidate, got)
				continue
			}
		}
		probed, err := pr.Probe(ctx, candidate)
		if err != nil {
			lastErr = err
			continue
		}
		return probed, nil
	}
	return Binary{}, fmt.Errorf("%s: no usable engine binary (%w); set %s with --allow-env-bin or install it into %q", pr.Kind, lastErr, pr.EnvVar, enginesDir)
}

// LoadDigests reads a sha256sum-format manifest (hex digest, whitespace,
// file name) from dir. It returns the name-to-digest map, or an error when
// the manifest is missing or malformed.
func LoadDigests(dir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, digestManifestName))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("supervise: malformed digest manifest line %q", line)
		}
		name := strings.TrimPrefix(fields[1], "*")
		name = filepath.Base(name)
		if len(fields[0]) != sha256.Size*2 {
			return nil, fmt.Errorf("supervise: malformed digest for %q", name)
		}
		out[name] = strings.ToLower(fields[0])
	}
	if len(out) == 0 {
		return nil, errors.New("supervise: empty digest manifest")
	}
	return out, nil
}

// VerifyDigest compares the binary against the checksum the updater recorded.
func (b Binary) VerifyDigest(expected string) error {
	if expected == "" {
		return fmt.Errorf("%s: no expected digest", b.Kind)
	}
	raw, err := os.ReadFile(b.Path)
	if err != nil {
		return fmt.Errorf("%s: read binary: %w", b.Kind, err)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(strings.TrimSpace(expected)))) != 1 {
		return fmt.Errorf("%s: digest mismatch: got %s", b.Kind, got)
	}
	return nil
}
