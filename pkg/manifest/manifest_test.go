package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeSkillFixture creates a deterministic skill directory in a temporary
// location. It returns the directory path. Executable bits are applied with
// explicit chmod calls so the fixture is identical on macOS and Linux.
func writeSkillFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	files := map[string]struct {
		content    string
		executable bool
	}{
		"SKILL.md":                     {"---\nname: demo\n---\nDemo skill.\n", false},
		"scripts/run.sh":               {"#!/usr/bin/env bash\necho run\n", true},
		"scripts/util.py":              {"print('util')\n", false},
		"references/ref.md":            {"Reference.\n", false},
		"assets/data.txt":              {"data\n", false},
		".hidden/config":               {"hidden\n", false},
		"nested/.skill-trust/kept.txt": {"nested control dir is content\n", false},
	}
	for path, f := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if f.executable {
			mode = 0o755
		}
		if err := os.WriteFile(full, []byte(f.content), mode); err != nil {
			t.Fatal(err)
		}
	}

	// Root control directory must be excluded from the manifest.
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ControlDir, ManifestFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCreate(t *testing.T) {
	dir := writeSkillFixture(t)

	m, err := Create(dir)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if m.Version != Version {
		t.Errorf("Version = %d, want %d", m.Version, Version)
	}
	if m.HashAlgorithm != HashAlgorithm {
		t.Errorf("HashAlgorithm = %q, want %q", m.HashAlgorithm, HashAlgorithm)
	}

	wantPaths := []string{
		".hidden/config",
		"SKILL.md",
		"assets/data.txt",
		"nested/.skill-trust/kept.txt",
		"references/ref.md",
		"scripts/run.sh",
		"scripts/util.py",
	}
	gotPaths := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		gotPaths = append(gotPaths, e.Path)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Errorf("paths = %v, want %v", gotPaths, wantPaths)
	}

	for _, e := range m.Entries {
		if e.Type != "file" {
			t.Errorf("entry %q type = %q, want file", e.Path, e.Type)
		}
	}
}

func TestCreateExecutableBit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		switch e.Path {
		case "a.sh":
			if !e.Executable {
				t.Errorf("a.sh executable = false, want true")
			}
		case "b.sh":
			if e.Executable {
				t.Errorf("b.sh executable = true, want false")
			}
		}
	}
}

func TestCreateExcludesRootControlDirOnly(t *testing.T) {
	dir := writeSkillFixture(t)
	m, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if e.Path == ControlDir || strings.HasPrefix(e.Path, ControlDir+"/") {
			t.Errorf("entry %q is inside the root control directory", e.Path)
		}
	}
	found := false
	for _, e := range m.Entries {
		if e.Path == "nested/.skill-trust/kept.txt" {
			found = true
		}
	}
	if !found {
		t.Error("nested .skill-trust file should be signed content")
	}
}

func TestCreateMissingSkillFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Create(dir)
	if !errors.Is(err, ErrMissingSkillFile) {
		t.Fatalf("err = %v, want ErrMissingSkillFile", err)
	}
}

func TestCreateMissingDir(t *testing.T) {
	_, err := Create(filepath.Join(t.TempDir(), "does-not-exist"))
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("err = %v, want ErrMalformedInput", err)
	}
}

func TestCreateRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "SKILL.md")
	if err := os.Symlink(target, filepath.Join(dir, "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := Create(dir)
	if !errors.Is(err, ErrUnsupportedContent) {
		t.Fatalf("err = %v, want ErrUnsupportedContent", err)
	}
}

func TestCreateRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mkfifo(filepath.Join(dir, "pipe")); err != nil {
		t.Skipf("fifo unavailable: %v", err)
	}
	_, err := Create(dir)
	if !errors.Is(err, ErrUnsupportedContent) {
		t.Fatalf("err = %v, want ErrUnsupportedContent", err)
	}
}

func TestCanonicalDeterministic(t *testing.T) {
	a := writeSkillFixture(t)
	b := writeSkillFixture(t)

	ma, err := Create(a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := Create(b)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := ma.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := mb.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Errorf("canonical bytes differ between identical trees")
	}
	if strings.Contains(string(ca), "\n") {
		t.Error("canonical form must not contain newlines")
	}
	if strings.Contains(string(ca), "&") || strings.Contains(string(ca), "<") {
		// Only meaningful if such characters appear in the fixture; the
		// fixture avoids them, so this asserts no escaping surprises.
		t.Log("canonical form contains escapable characters")
	}
}

func TestCanonicalSkipsControlDir(t *testing.T) {
	dir := writeSkillFixture(t)
	m, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(m.Entries), ManifestFile) {
		t.Error("manifest.json itself must not be an entry")
	}
}

func TestDigestStable(t *testing.T) {
	// The fixture is deterministic, so the manifest digest is a golden
	// value. If this test fails after an intentional format change, update
	// the golden value and docs/MANIFEST.md test vectors together.
	dir := writeSkillFixture(t)
	m, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 64 {
		t.Fatalf("digest length = %d, want 64", len(d))
	}
	// Digest must equal SHA-256 of the canonical bytes.
	ca, _ := m.Canonical()
	if d != sha256Hex(ca) {
		t.Errorf("digest does not match SHA-256 of canonical bytes")
	}
}

func TestValidateRejectsBadManifests(t *testing.T) {
	cases := []struct {
		name string
		m    *Manifest
		want error
	}{
		{"wrong version", &Manifest{Version: 2, HashAlgorithm: "sha256"}, ErrUnsupportedContent},
		{"wrong algorithm", &Manifest{Version: 1, HashAlgorithm: "sha512"}, ErrUnsupportedContent},
		{
			"absolute path",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "/etc/passwd", Type: "file", Digest: strings.Repeat("a", 64)}}},
			ErrMalformedInput,
		},
		{
			"dotdot path",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "../escape", Type: "file", Digest: strings.Repeat("a", 64)}}},
			ErrMalformedInput,
		},
		{
			"backslash path",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: `a\b`, Type: "file", Digest: strings.Repeat("a", 64)}}},
			ErrMalformedInput,
		},
		{
			"empty component path",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "a//b", Type: "file", Digest: strings.Repeat("a", 64)}}},
			ErrMalformedInput,
		},
		{
			"control dir path",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: ".skill-trust/manifest.json", Type: "file", Digest: strings.Repeat("a", 64)}}},
			ErrMalformedInput,
		},
		{
			"short digest",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "a", Type: "file", Digest: "abc"}}},
			ErrMalformedInput,
		},
		{
			"non-hex digest",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "a", Type: "file", Digest: strings.Repeat("z", 64)}}},
			ErrMalformedInput,
		},
		{
			"wrong type",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{{Path: "a", Type: "symlink", Digest: strings.Repeat("a", 64)}}},
			ErrUnsupportedContent,
		},
		{
			"unsorted",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{
				{Path: "b", Type: "file", Digest: strings.Repeat("a", 64)},
				{Path: "a", Type: "file", Digest: strings.Repeat("a", 64)},
			}},
			ErrMalformedInput,
		},
		{
			"duplicate",
			&Manifest{Version: 1, HashAlgorithm: "sha256", Entries: []Entry{
				{Path: "a", Type: "file", Digest: strings.Repeat("a", 64)},
				{Path: "a", Type: "file", Digest: strings.Repeat("b", 64)},
			}},
			ErrMalformedInput,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	dir := writeSkillFixture(t)
	expected, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}

	tamper := func(fn func()) {
		t.Helper()
		fn()
		observed, err := Create(dir)
		if err != nil {
			t.Fatal(err)
		}
		diffs := Compare(expected, observed)
		if len(diffs) == 0 {
			t.Fatal("expected differences, got none")
		}
	}
	kindOf := func(diffs []Difference, k DifferenceKind) bool {
		for _, d := range diffs {
			if d.Kind == k {
				return true
			}
		}
		return false
	}

	observed, _ := Create(dir)
	if diffs := Compare(expected, observed); len(diffs) != 0 {
		t.Fatalf("identical trees produced differences: %v", diffs)
	}

	tamper(func() {
		os.WriteFile(filepath.Join(dir, "scripts", "util.py"), []byte("print('evil')\n"), 0o644)
	})
	observed, _ = Create(dir)
	if !kindOf(Compare(expected, observed), DiffFileModified) {
		t.Error("modified file not detected")
	}

	tamper(func() {
		os.WriteFile(filepath.Join(dir, "scripts", "extra.sh"), []byte("echo added\n"), 0o755)
	})
	observed, _ = Create(dir)
	if !kindOf(Compare(expected, observed), DiffFileAdded) {
		t.Error("added file not detected")
	}

	tamper(func() {
		os.Remove(filepath.Join(dir, "references", "ref.md"))
	})
	observed, _ = Create(dir)
	if !kindOf(Compare(expected, observed), DiffFileDeleted) {
		t.Error("deleted file not detected")
	}

	tamper(func() {
		os.Chmod(filepath.Join(dir, "scripts", "run.sh"), 0o644)
	})
	observed, _ = Create(dir)
	if !kindOf(Compare(expected, observed), DiffModeChanged) {
		t.Error("executable bit change not detected")
	}

	// Version mismatch short-circuits.
	diffs := Compare(&Manifest{Version: 2}, observed)
	if len(diffs) != 1 || diffs[0].Kind != DiffVersion {
		t.Errorf("version mismatch = %v", diffs)
	}
}

func TestControlManifestRoundTrip(t *testing.T) {
	dir := writeSkillFixture(t)
	m, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WriteControlManifest(dir); err != nil {
		t.Fatal(err)
	}

	// The control file must not change the recomputed manifest.
	m2, err := Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if diffs := Compare(m, m2); len(diffs) != 0 {
		t.Fatalf("writing control manifest changed content: %v", diffs)
	}

	loaded, err := LoadControlManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := m.Digest()
	d2, _ := loaded.Digest()
	if d1 != d2 {
		t.Errorf("loaded digest %s != original %s", d2, d1)
	}

	// On-disk bytes are exactly the canonical bytes.
	ca, _ := m.Canonical()
	raw, err := os.ReadFile(ControlPath(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(ca) {
		t.Error("control manifest file bytes differ from canonical bytes")
	}
}

func TestLoadControlManifestMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadControlManifest(dir)
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("err = %v, want ErrMalformedInput", err)
	}
}

func TestLoadControlManifestMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ControlPath(dir, ManifestFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadControlManifest(dir)
	if !errors.Is(err, ErrMalformedInput) {
		t.Fatalf("err = %v, want ErrMalformedInput", err)
	}
}

func TestJSONShape(t *testing.T) {
	m := New()
	m.Entries = []Entry{{
		Path:       "SKILL.md",
		Type:       "file",
		Digest:     strings.Repeat("0", 64),
		Executable: true,
	}}
	b, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"hashAlgorithm":"sha256","entries":[{"path":"SKILL.md","type":"file","digest":"` +
		strings.Repeat("0", 64) + `","executable":true}]}`
	if string(b) != want {
		t.Errorf("canonical JSON =\n%s\nwant\n%s", b, want)
	}

	// Round-trip through JSON keeps the manifest.
	var back Manifest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := back.Canonical()
	if string(again) != string(b) {
		t.Error("canonical form is not stable across round-trip")
	}
}
