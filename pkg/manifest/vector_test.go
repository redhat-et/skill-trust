package manifest

import (
	"path/filepath"
	"strings"
	"testing"
)

// The demo-skill fixture is the canonical manifest test vector. The values
// below are the golden outputs for the exact bytes stored in
// testdata/demo-skill (including the executable bit on scripts/run.sh,
// preserved by git). They are also published in docs/MANIFEST.md. If this
// test fails after an intentional format change, update the golden values
// and the documentation together.
const (
	demoSkillCanonical = `{"version":1,"hashAlgorithm":"sha256","entries":[` +
		`{"path":".hidden/config","type":"file","digest":"d1f95eaf7d431936847daf8517ac54ede46d3465a74746397c4437ba844a01df","executable":false},` +
		`{"path":"SKILL.md","type":"file","digest":"9fc689ab01291c9812d2b6b449eb3db80f72b5d7e3fb818cb532b75829064906","executable":false},` +
		`{"path":"assets/data.txt","type":"file","digest":"4c868ef8cdcb0a56d4abaaf91dd8d0a6a988d240f51bb1d66199a9878896abbd","executable":false},` +
		`{"path":"references/ref.md","type":"file","digest":"4829612c1ad61166ca3077ae244799d0a97528972df7eb1e5267fdf8b7f34922","executable":false},` +
		`{"path":"scripts/run.sh","type":"file","digest":"d087ce4ba31bbdd61cac64d1e2d3244ff6810e60dd4cc2dff1c1706dbde578eb","executable":true},` +
		`{"path":"scripts/util.py","type":"file","digest":"aaf9f035bf3a9364c1dbf0d1df6ce9e8508e83cfb532b818bfa1b2fc5b6fc3ca","executable":false}]}`

	demoSkillDigest = "9a360f711d6d044b9a4de25c80cdf5035e9293e5d0845230231f7327324824d8"
)

func TestVectorDemoSkill(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "demo-skill")

	m, err := Create(dir)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ca, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != demoSkillCanonical {
		t.Errorf("canonical JSON mismatch:\ngot:  %s\nwant: %s", ca, demoSkillCanonical)
	}

	d, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != demoSkillDigest {
		t.Errorf("manifest digest = %s, want %s", d, demoSkillDigest)
	}

	// The canonical form must be a single line with no HTML escaping and
	// sorted paths.
	if strings.Contains(string(ca), "\n") {
		t.Error("canonical form contains newlines")
	}
}
