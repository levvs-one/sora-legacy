package control_test

// Three-way mirror pin for the sora.core.v1 contract (final pass 3).
//
// The contract lives in four places that must agree:
//
//   - proto/sora/core/v1/core_control.proto — the source text;
//   - core/gen (protoc-gen-go) — the descriptor this package serves,
//     checked here field by field against the proto text, so a stale
//     or hand-edited generation is a red test, not a silent drift;
//   - app/lib/src/generated (protoc-gen-dart) — the Dart client stub,
//     checked by its method paths against the same descriptor;
//   - the hand-written consumers that derive method names instead of
//     generating them: the C# client (legacy/Control/CoreConnection.cs
//     strips the "Request" suffix off the request message name to get
//     the RPC name) and core/legacycontrol, which dispatches
//     generically over the generated service descriptor. Both are
//     sound exactly when every method's messages are named
//     <Method>Request (and <Method>Response for unary methods),
//     pinned below.
//
// The Server itself embeds UnimplementedCoreControlServer, so the
// compiler cannot prove every RPC is implemented; the last check
// reads the package sources and requires a concrete
// `func (s *Server) <Method>` per RPC.
//
// The contract version is also spelled by hand in four places (the
// core, the macOS helper, the C# client). The triples are pinned
// exactly as they stand today — note the C# client deliberately
// floors itself at 1.7 (MinSupportedMinor 7) while the Go peers
// floor at 1; the asymmetry is recorded here so any change to any
// of the four spellings is a deliberate, visible act.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
)

func mirrorRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "proto", "sora", "core", "v1", "core_control.proto")); err != nil {
		t.Fatalf("repository root not found from the control package: %v", err)
	}
	return root
}

func readMirrorFile(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func coreControlService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	file := (&corev1.HandshakeRequest{}).ProtoReflect().Descriptor().ParentFile()
	svc := file.Services().ByName("CoreControl")
	if svc == nil {
		t.Fatal("the generated descriptor has no CoreControl service")
	}
	return svc
}

// protoRPC is one rpc line of the proto text.
type protoRPC struct {
	request, response string
	serverStreaming   bool
}

var rpcLine = regexp.MustCompile(`rpc\s+(\w+)\((\w+)\)\s+returns\s+\((stream\s+)?(\w+)\)`)

func protoRPCs(t *testing.T, proto string) map[string]protoRPC {
	t.Helper()
	out := map[string]protoRPC{}
	for _, m := range rpcLine.FindAllStringSubmatch(proto, -1) {
		out[m[1]] = protoRPC{request: m[2], response: m[4], serverStreaming: m[3] != ""}
	}
	if len(out) == 0 {
		t.Fatal("no rpc lines parsed from the proto text")
	}
	return out
}

func TestContractMirrorProtoVsGeneratedDescriptor(t *testing.T) {
	root := mirrorRoot(t)
	proto := readMirrorFile(t, root, "proto/sora/core/v1/core_control.proto")
	want := protoRPCs(t, proto)
	svc := coreControlService(t)
	methods := svc.Methods()
	if methods.Len() != len(want) {
		t.Fatalf("descriptor carries %d methods, the proto text declares %d", methods.Len(), len(want))
	}
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		p, ok := want[string(m.Name())]
		if !ok {
			t.Errorf("descriptor method %s is not in the proto text (stale generation?)", m.Name())
			continue
		}
		if string(m.Input().Name()) != p.request || string(m.Output().Name()) != p.response {
			t.Errorf("%s: descriptor speaks %s -> %s, the proto text says %s -> %s",
				m.Name(), m.Input().Name(), m.Output().Name(), p.request, p.response)
		}
		if m.IsStreamingServer() != p.serverStreaming {
			t.Errorf("%s: descriptor streaming=%v, the proto text says %v", m.Name(), m.IsStreamingServer(), p.serverStreaming)
		}
		// The hand-written generic consumers (see the file comment)
		// derive the RPC name from the request message name; that
		// derivation is sound only under this naming shape. A
		// streaming method returns its stream element instead of a
		// <Method>Response message, so the shape binds the request
		// always and the response only for unary methods.
		if p.request != string(m.Name())+"Request" {
			t.Errorf("%s: request message %s breaks the <Method>Request shape the C# client derives method names from",
				m.Name(), p.request)
		}
		if !p.serverStreaming && p.response != string(m.Name())+"Response" {
			t.Errorf("%s: response message %s breaks the <Method>Response shape of unary methods",
				m.Name(), p.response)
		}
	}
}

// protoMessageFields extracts message and enum field numbers from the
// proto text: for every message, field name -> number; for every
// enum, value name -> number.
func protoMessageFields(t *testing.T, proto string) (map[string]map[string]int32, map[string]map[string]int32) {
	t.Helper()
	// Strip comments so commented-out declarations cannot pose as fields.
	var lines []string
	for _, line := range strings.Split(proto, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, line)
	}
	text := strings.Join(lines, "\n")
	blocks := func(kind string) map[string]string {
		out := map[string]string{}
		re := regexp.MustCompile(`(?s)\b` + kind + `\s+(\w+)\s*\{`)
		for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
			name := text[loc[2]:loc[3]]
			depth, j := 1, loc[1]
			for ; j < len(text) && depth > 0; j++ {
				switch text[j] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			out[name] = text[loc[1]:j]
		}
		return out
	}
	// Fields may share one line (message X { A a = 1; B b = 2; }), so
	// this pattern is deliberately not line-anchored either.
	fieldLine := regexp.MustCompile(`(?:repeated\s+)?[\w.]+(?:\s*<[^>]*>)?\s+(\w+)\s*=\s*(\d+)\s*;`)
	messages := map[string]map[string]int32{}
	for name, body := range blocks("message") {
		fields := map[string]int32{}
		for _, m := range fieldLine.FindAllStringSubmatch(body, -1) {
			n, err := strconv.ParseInt(m[2], 10, 32)
			if err != nil {
				t.Fatalf("message %s field %s: %v", name, m[1], err)
			}
			fields[m[1]] = int32(n)
		}
		messages[name] = fields
	}
	// Enum values may share one line (enum TunnelMode { ... = 0; ... = 1; }),
	// so this pattern is deliberately not line-anchored.
	enumLine := regexp.MustCompile(`([A-Z][A-Z0-9_]*)\s*=\s*(\d+)\s*;`)
	enums := map[string]map[string]int32{}
	for name, body := range blocks("enum") {
		values := map[string]int32{}
		for _, m := range enumLine.FindAllStringSubmatch(body, -1) {
			n, err := strconv.ParseInt(m[2], 10, 32)
			if err != nil {
				t.Fatalf("enum %s value %s: %v", name, m[1], err)
			}
			values[m[1]] = int32(n)
		}
		enums[name] = values
	}
	return messages, enums
}

func TestContractMirrorProtoFieldsVsGeneratedDescriptor(t *testing.T) {
	root := mirrorRoot(t)
	proto := readMirrorFile(t, root, "proto/sora/core/v1/core_control.proto")
	wantMsg, wantEnum := protoMessageFields(t, proto)
	file := (&corev1.HandshakeRequest{}).ProtoReflect().Descriptor().ParentFile()

	var walkMessages func(list protoreflect.MessageDescriptors)
	seenMsg := map[string]bool{}
	walkMessages = func(list protoreflect.MessageDescriptors) {
		for i := 0; i < list.Len(); i++ {
			md := list.Get(i)
			name := string(md.Name())
			seenMsg[name] = true
			want, ok := wantMsg[name]
			if !ok {
				t.Errorf("generated message %s has no proto message block", name)
				continue
			}
			fields := md.Fields()
			if fields.Len() != len(want) {
				t.Errorf("message %s: descriptor carries %d fields, the proto text declares %d", name, fields.Len(), len(want))
			}
			for j := 0; j < fields.Len(); j++ {
				f := fields.Get(j)
				// Map entries are synthetic messages, handled by the
				// walk; the field itself is compared by number.
				if n, ok := want[string(f.Name())]; !ok || n != int32(f.Number()) {
					t.Errorf("message %s field %s: descriptor number %d, the proto text says %d (present=%v)",
						name, f.Name(), f.Number(), want[string(f.Name())], ok)
				}
			}
			walkMessages(md.Messages())
		}
	}
	walkMessages(file.Messages())
	for name := range wantMsg {
		if !seenMsg[name] {
			t.Errorf("proto message %s is missing from the generated descriptor (stale generation?)", name)
		}
	}

	var walkEnums func(list protoreflect.EnumDescriptors)
	seenEnum := map[string]bool{}
	walkEnums = func(list protoreflect.EnumDescriptors) {
		for i := 0; i < list.Len(); i++ {
			ed := list.Get(i)
			name := string(ed.Name())
			seenEnum[name] = true
			want, ok := wantEnum[name]
			if !ok {
				t.Errorf("generated enum %s has no proto enum block", name)
				continue
			}
			values := ed.Values()
			if values.Len() != len(want) {
				t.Errorf("enum %s: descriptor carries %d values, the proto text declares %d", name, values.Len(), len(want))
			}
			for j := 0; j < values.Len(); j++ {
				v := values.Get(j)
				if n, ok := want[string(v.Name())]; !ok || n != int32(v.Number()) {
					t.Errorf("enum %s value %s: descriptor number %d, the proto text says %d (present=%v)",
						name, v.Name(), v.Number(), want[string(v.Name())], ok)
				}
			}
		}
	}
	walkEnums(file.Enums())
	// Enums nested in messages are not used by this contract; if one
	// appears, extend the walk rather than silently skipping it.
	for name := range wantEnum {
		if !seenEnum[name] {
			t.Errorf("proto enum %s is missing from the generated descriptor (stale generation?)", name)
		}
	}
}

func TestContractMirrorDartStubVsDescriptor(t *testing.T) {
	root := mirrorRoot(t)
	dart := readMirrorFile(t, root, "app/lib/src/generated/sora/core/v1/core_control.pbgrpc.dart")
	re := regexp.MustCompile(`'/sora\.core\.v1\.CoreControl/(\w+)'`)
	got := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(dart, -1) {
		got[m[1]] = true
	}
	svc := coreControlService(t)
	methods := svc.Methods()
	if len(got) != methods.Len() {
		t.Fatalf("the Dart stub carries %d method paths, the descriptor carries %d methods", len(got), methods.Len())
	}
	for i := 0; i < methods.Len(); i++ {
		if !got[string(methods.Get(i).Name())] {
			t.Errorf("method %s is missing from the Dart stub (stale generation?)", methods.Get(i).Name())
		}
	}
}

func TestContractMirrorServerImplementsEveryRPC(t *testing.T) {
	root := mirrorRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "core", "control"))
	if err != nil {
		t.Fatal(err)
	}
	impl := regexp.MustCompile(`func \(s \*Server\) (\w+)\(`)
	have := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src := readMirrorFile(t, root, "core/control/"+name)
		for _, m := range impl.FindAllStringSubmatch(src, -1) {
			have[m[1]] = true
		}
	}
	svc := coreControlService(t)
	methods := svc.Methods()
	var missing []string
	for i := 0; i < methods.Len(); i++ {
		if !have[string(methods.Get(i).Name())] {
			missing = append(missing, string(methods.Get(i).Name()))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("RPCs with no concrete Server implementation (the embedded Unimplemented stub would answer): %v", missing)
	}
}

func TestContractMirrorVersionSpellings(t *testing.T) {
	root := mirrorRoot(t)
	parse := func(rel, pattern string) (int, int, int) {
		t.Helper()
		m := regexp.MustCompile(pattern).FindStringSubmatch(readMirrorFile(t, root, rel))
		if m == nil {
			t.Fatalf("%s: version spelling not found", rel)
		}
		var out [3]int
		for i := range out {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				t.Fatalf("%s: %v", rel, err)
			}
			out[i] = n
		}
		return out[0], out[1], out[2]
	}
	// The core itself: core/cmd/sora-core/main.go.
	maj, min, minSup := parse("core/cmd/sora-core/main.go",
		`Version\s*=\s*control\.Version\{Major:\s*(\d+),\s*Minor:\s*(\d+),\s*MinSupportedMinor:\s*(\d+)\}`)
	if maj != 1 || min != 7 || minSup != 1 {
		t.Errorf("core serves contract %d.%d (min %d), want 1.7 (min 1)", maj, min, minSup)
	}
	// The macOS helper client: macos/helper/client.go.
	maj, min, minSup = parse("macos/helper/client.go",
		`ApiVersion\{Major:\s*(\d+),\s*Minor:\s*(\d+),\s*MinSupportedMinor:\s*(\d+)\}`)
	if maj != 1 || min != 7 || minSup != 1 {
		t.Errorf("macOS helper speaks contract %d.%d (min %d), want 1.7 (min 1)", maj, min, minSup)
	}
	// The C# client: legacy/Control/CoreConnection.cs. Its floor is
	// deliberately stricter (min 7: the client refuses older cores);
	// the pin records the asymmetry instead of flattening it.
	maj, min, minSup = parse("legacy/Control/CoreConnection.cs",
		`ApiVersion\s*\{\s*Major\s*=\s*(\d+),\s*Minor\s*=\s*(\d+),\s*MinSupportedMinor\s*=\s*(\d+)\s*\}`)
	if maj != 1 || min != 7 || minSup != 7 {
		t.Errorf("C# client speaks contract %d.%d (min %d), want the recorded 1.7 (min 7)", maj, min, minSup)
	}
}
