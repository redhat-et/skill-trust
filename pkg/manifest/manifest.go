// Package manifest implements the skill-trust canonical skill manifest.
//
// The manifest is a complete, deterministic description of a skill
// directory's content: every regular file outside the reserved
// .skill-trust/ control directory, represented as a normalized relative
// path, a SHA-256 content digest, and the executable permission bit.
//
// The canonical serialization of the manifest is the signed subject: its
// SHA-256 digest is what signing operates on and what verification
// recomputes.
//
// The package never executes, imports, or interprets skill content.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Format constants for manifest v1.
const (
	// Version is the current manifest format version.
	Version = 1

	// HashAlgorithm is the only content hash algorithm supported in v1.
	HashAlgorithm = "sha256"

	// ControlDir is the reserved control directory at the skill root,
	// excluded from the signed content.
	ControlDir = ".skill-trust"

	// ManifestFile is the canonical manifest control file name.
	ManifestFile = "manifest.json"

	// BundleFile is the signature bundle control file name.
	BundleFile = "bundle.sigstore.json"

	// ReportFile is the optional verification report control file name.
	ReportFile = "report.json"

	// SkillFile is the required skill instruction file at the skill root.
	SkillFile = "SKILL.md"

	// entryTypeFile is the only entry type in v1.
	entryTypeFile = "file"
)

// Error kinds. Errors returned by this package wrap one of these values so
// callers can distinguish malformed input from unsupported content without
// matching on strings.
var (
	// ErrMalformedInput indicates the skill directory or control file could
	// not be read or parsed (missing file, bad JSON, structural violation).
	ErrMalformedInput = errors.New("malformed input")

	// ErrUnsupportedContent indicates the skill directory contains an
	// entry type that manifest v1 rejects (symlink, device, socket, FIFO).
	ErrUnsupportedContent = errors.New("unsupported content")

	// ErrMissingSkillFile indicates the directory has no SKILL.md at its
	// root and therefore is not an Agent Skill.
	ErrMissingSkillFile = errors.New("missing SKILL.md")
)

// Entry describes one regular file in the signed content.
type Entry struct {
	// Path is the normalized, slash-separated path relative to the skill
	// root. It is never absolute and never contains ".", "..", or empty
	// components.
	Path string `json:"path"`

	// Type is the entry type; only "file" exists in v1.
	Type string `json:"type"`

	// Digest is the lowercase hex SHA-256 of the file content.
	Digest string `json:"digest"`

	// Executable reports whether any execute permission bit is set on the
	// file (mode & 0111 != 0).
	Executable bool `json:"executable"`
}

// Manifest is the canonical description of a skill directory.
type Manifest struct {
	Version       int     `json:"version"`
	HashAlgorithm string  `json:"hashAlgorithm"`
	Entries       []Entry `json:"entries"`
}

// New returns an empty manifest with the v1 header fields set.
func New() *Manifest {
	return &Manifest{
		Version:       Version,
		HashAlgorithm: HashAlgorithm,
		Entries:       []Entry{},
	}
}

// Create walks the skill directory rooted at dir and builds its manifest.
//
// Every regular file below dir is included, including hidden files and
// files outside the conventional scripts/, references/, and assets/
// directories, except files below the root .skill-trust/ control
// directory. SKILL.md must exist at the root. Symlinks and other
// non-regular entries are rejected.
//
// Create performs no signature or policy evaluation and never executes
// skill content.
func Create(dir string) (*Manifest, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}

	rootInfo, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("%w: %q is not a directory", ErrMalformedInput, dir)
	}
	if _, err := os.Stat(filepath.Join(abs, SkillFile)); err != nil {
		return nil, fmt.Errorf("%w: %s is required at the skill root", ErrMissingSkillFile, SkillFile)
	}

	m := New()

	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(abs, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}

		// Skip the reserved control directory at the skill root.
		if rel == ControlDir {
			return filepath.SkipDir
		}
		// Any nested .skill-trust directory is ordinary content.

		switch {
		case d.Type().IsRegular():
			// fall through to hashing below
		case d.IsDir():
			return nil
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("%w: symlink at %q is rejected in manifest v1", ErrUnsupportedContent, rel)
		default:
			return fmt.Errorf("%w: special filesystem entry at %q is rejected in manifest v1", ErrUnsupportedContent, rel)
		}

		entry, err := entryFor(abs, rel)
		if err != nil {
			return err
		}
		m.Entries = append(m.Entries, entry)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(m.Entries, func(i, j int) bool {
		return m.Entries[i].Path < m.Entries[j].Path
	})

	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// entryFor hashes one file and returns its manifest entry.
func entryFor(root, rel string) (Entry, error) {
	full := filepath.Join(root, filepath.FromSlash(rel))

	f, err := os.Open(full)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}

	info, err := f.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	if !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("%w: %q changed type during manifest creation", ErrUnsupportedContent, rel)
	}

	return Entry{
		Path:       rel,
		Type:       entryTypeFile,
		Digest:     hex.EncodeToString(h.Sum(nil)),
		Executable: info.Mode().Perm()&0o111 != 0,
	}, nil
}

// Validate checks the structural invariants of a manifest: correct version,
// supported hash algorithm, normalized sorted unique paths, file entry
// types, and well-formed digests. It does not touch the filesystem.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrMalformedInput)
	}
	if m.Version != Version {
		return fmt.Errorf("%w: unsupported manifest version %d (supported: %d)", ErrUnsupportedContent, m.Version, Version)
	}
	if m.HashAlgorithm != HashAlgorithm {
		return fmt.Errorf("%w: unsupported hash algorithm %q (supported: %q)", ErrUnsupportedContent, m.HashAlgorithm, HashAlgorithm)
	}
	seen := make(map[string]struct{}, len(m.Entries))
	previous := ""
	for i, e := range m.Entries {
		if e.Type != entryTypeFile {
			return fmt.Errorf("%w: entry %q has unsupported type %q", ErrUnsupportedContent, e.Path, e.Type)
		}
		if err := validatePath(e.Path); err != nil {
			return err
		}
		if e.Path == ControlDir || strings.HasPrefix(e.Path, ControlDir+"/") {
			return fmt.Errorf("%w: entry %q is inside the reserved control directory", ErrMalformedInput, e.Path)
		}
		if len(e.Digest) != sha256.Size*2 {
			return fmt.Errorf("%w: entry %q has malformed digest", ErrMalformedInput, e.Path)
		}
		if _, err := hex.DecodeString(e.Digest); err != nil {
			return fmt.Errorf("%w: entry %q has malformed digest: %v", ErrMalformedInput, e.Path, err)
		}
		if _, dup := seen[e.Path]; dup {
			return fmt.Errorf("%w: duplicate path %q", ErrMalformedInput, e.Path)
		}
		seen[e.Path] = struct{}{}
		if i > 0 && e.Path < previous {
			return fmt.Errorf("%w: entries are not sorted by path at %q", ErrMalformedInput, e.Path)
		}
		previous = e.Path
	}
	return nil
}

// validatePath enforces normalized, relative, slash-separated paths.
func validatePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrMalformedInput)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: absolute path %q", ErrMalformedInput, p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("%w: path %q uses backslash separators", ErrMalformedInput, p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" {
			return fmt.Errorf("%w: path %q has an empty component", ErrMalformedInput, p)
		}
		if part == "." || part == ".." {
			return fmt.Errorf("%w: path %q has a %q component", ErrMalformedInput, p, part)
		}
	}
	return nil
}

// Canonical returns the canonical JSON serialization of the manifest.
//
// The canonical form is compact JSON (no insignificant whitespace), UTF-8,
// with HTML escaping disabled, struct field order for key order, entries in
// sorted order, and no trailing newline. The SHA-256 of these bytes is the
// manifest digest used as the signing subject.
func (m *Manifest) Canonical() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}

// Digest returns the lowercase hex SHA-256 of the canonical serialization.
func (m *Manifest) Digest() (string, error) {
	b, err := m.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ControlPath returns the path of a file inside the control directory of
// the skill rooted at dir.
func ControlPath(dir, name string) string {
	return filepath.Join(dir, ControlDir, name)
}

// LoadControlManifest reads and parses .skill-trust/manifest.json from the
// skill rooted at dir. The returned manifest is validated but is not
// compared against the directory contents; use Compare for that.
func LoadControlManifest(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(ControlPath(dir, ManifestFile))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// WriteControlManifest writes the canonical serialization of m to
// .skill-trust/manifest.json under dir. The bytes on disk are exactly the
// canonical bytes, so the digest of the file equals the manifest digest.
func (m *Manifest) WriteControlManifest(dir string) error {
	b, err := m.Canonical()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, ControlDir), 0o755); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	if err := os.WriteFile(ControlPath(dir, ManifestFile), b, 0o644); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedInput, err)
	}
	return nil
}

// Difference describes one mismatch between an embedded (expected)
// manifest and a recomputed (observed) manifest.
type Difference struct {
	Kind    DifferenceKind `json:"kind"`
	Path    string         `json:"path,omitempty"`
	Details string         `json:"details"`
}

// DifferenceKind enumerates manifest comparison outcomes.
type DifferenceKind string

// Difference kinds.
const (
	DiffVersion       DifferenceKind = "version-mismatch"
	DiffHashAlgorithm DifferenceKind = "hash-algorithm-mismatch"
	DiffFileModified  DifferenceKind = "file-modified"
	DiffFileAdded     DifferenceKind = "file-added"
	DiffFileDeleted   DifferenceKind = "file-deleted"
	DiffModeChanged   DifferenceKind = "executable-bit-changed"
)

// Compare returns the differences between the embedded manifest expected
// and the recomputed manifest observed. An empty slice means the content is
// identical. Version and hash algorithm mismatches are reported and
// comparison stops, since digests are not comparable across algorithms.
func Compare(expected, observed *Manifest) []Difference {
	if expected.Version != observed.Version {
		return []Difference{{
			Kind:    DiffVersion,
			Details: fmt.Sprintf("embedded manifest version %d, recomputed %d", expected.Version, observed.Version),
		}}
	}
	if expected.HashAlgorithm != observed.HashAlgorithm {
		return []Difference{{
			Kind:    DiffHashAlgorithm,
			Details: fmt.Sprintf("embedded hash algorithm %q, recomputed %q", expected.HashAlgorithm, observed.HashAlgorithm),
		}}
	}

	var diffs []Difference
	observedByPath := make(map[string]Entry, len(observed.Entries))
	for _, e := range observed.Entries {
		observedByPath[e.Path] = e
	}
	expectedByPath := make(map[string]Entry, len(expected.Entries))
	for _, e := range expected.Entries {
		expectedByPath[e.Path] = e
	}

	for _, e := range expected.Entries {
		o, ok := observedByPath[e.Path]
		if !ok {
			diffs = append(diffs, Difference{Kind: DiffFileDeleted, Path: e.Path, Details: fmt.Sprintf("signed file %q is missing", e.Path)})
			continue
		}
		if e.Digest != o.Digest {
			diffs = append(diffs, Difference{Kind: DiffFileModified, Path: e.Path, Details: fmt.Sprintf("signed file %q content changed (expected sha256:%s, observed sha256:%s)", e.Path, e.Digest, o.Digest)})
		}
		if e.Executable != o.Executable {
			diffs = append(diffs, Difference{Kind: DiffModeChanged, Path: e.Path, Details: fmt.Sprintf("signed file %q executable bit changed (expected %t, observed %t)", e.Path, e.Executable, o.Executable)})
		}
	}
	for _, e := range observed.Entries {
		if _, ok := expectedByPath[e.Path]; !ok {
			diffs = append(diffs, Difference{Kind: DiffFileAdded, Path: e.Path, Details: fmt.Sprintf("unsigned file %q was added", e.Path)})
		}
	}
	return diffs
}
