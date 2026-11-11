package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateRoundTrip(t *testing.T) {
	tmp := t.TempDir()

	state := State{
		"/skills/demo": Record{
			Allowed:    true,
			Digest:     "abcd1234",
			VerifiedAt: time.Now().UTC().Truncate(time.Second),
		},
		"/skills/other": Record{
			Allowed:    false,
			Digest:     "",
			VerifiedAt: time.Now().UTC().Truncate(time.Second),
		},
	}

	sessionID := "session-123"

	err := SaveState(tmp, sessionID, state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded := LoadState(tmp, sessionID)

	if len(loaded) != len(state) {
		t.Errorf("loaded state has %d entries, want %d", len(loaded), len(state))
	}

	for root, want := range state {
		got, ok := loaded[root]
		if !ok {
			t.Errorf("missing root %s in loaded state", root)
			continue
		}
		if got.Allowed != want.Allowed {
			t.Errorf("root %s: Allowed = %v, want %v", root, got.Allowed, want.Allowed)
		}
		if got.Digest != want.Digest {
			t.Errorf("root %s: Digest = %q, want %q", root, got.Digest, want.Digest)
		}
		if !got.VerifiedAt.Equal(want.VerifiedAt) {
			t.Errorf("root %s: VerifiedAt = %v, want %v", root, got.VerifiedAt, want.VerifiedAt)
		}
	}
}

func TestLoadStateCorruptJSON(t *testing.T) {
	tmp := t.TempDir()
	sessionID := "corrupt-session"

	// Write corrupt JSON
	stateFile := filepath.Join(tmp, "state-"+sessionID+".json")
	os.WriteFile(stateFile, []byte("{corrupt"), 0o600)

	// Should return empty state, not error
	state := LoadState(tmp, sessionID)
	if len(state) != 0 {
		t.Errorf("LoadState with corrupt JSON returned %d entries, want 0", len(state))
	}
}

func TestLoadStateJSONNull(t *testing.T) {
	tmp := t.TempDir()
	sessionID := "null-session"

	// Write JSON null
	stateFile := filepath.Join(tmp, "state-"+sessionID+".json")
	os.WriteFile(stateFile, []byte("null"), 0o600)

	// Should return empty non-nil State
	state := LoadState(tmp, sessionID)
	if state == nil {
		t.Error("LoadState with JSON null returned nil, want empty non-nil State")
	}
	if len(state) != 0 {
		t.Errorf("LoadState with JSON null returned %d entries, want 0", len(state))
	}
}

func TestLoadStateMissing(t *testing.T) {
	tmp := t.TempDir()

	// Should return empty state when file doesn't exist
	state := LoadState(tmp, "nonexistent")
	if len(state) != 0 {
		t.Errorf("LoadState with missing file returned %d entries, want 0", len(state))
	}
}

func TestSanitizedSessionID(t *testing.T) {
	tmp := t.TempDir()

	// Test that path traversal is prevented
	state := State{
		"/test": Record{Allowed: true, Digest: "test", VerifiedAt: time.Now()},
	}

	// Try to save with a dangerous session ID
	dangerousID := "../../../etc/passwd"
	err := SaveState(tmp, dangerousID, state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Verify it stayed inside tmp
	entries, _ := os.ReadDir(tmp)
	foundOutside := false
	for _, e := range entries {
		if filepath.IsAbs(e.Name()) || filepath.Dir(e.Name()) != "." {
			foundOutside = true
		}
	}
	if foundOutside {
		t.Error("Session ID sanitization failed, file created outside state dir")
	}
}

func TestEmptySessionID(t *testing.T) {
	tmp := t.TempDir()

	state := State{
		"/test": Record{Allowed: true, Digest: "test", VerifiedAt: time.Now()},
	}

	// Empty session ID should become "unknown"
	err := SaveState(tmp, "", state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded := LoadState(tmp, "")
	if len(loaded) != 1 {
		t.Errorf("loaded state has %d entries, want 1", len(loaded))
	}

	// Also verify it can be loaded as "unknown"
	loadedUnknown := LoadState(tmp, "unknown")
	if len(loadedUnknown) != 1 {
		t.Errorf("loaded state with 'unknown' has %d entries, want 1", len(loadedUnknown))
	}
}

func TestPruneStates(t *testing.T) {
	tmp := t.TempDir()

	now := time.Now()
	maxAge := 24 * time.Hour

	// Create some state files with different modification times
	old1 := filepath.Join(tmp, "state-old1.json")
	old2 := filepath.Join(tmp, "state-old2.json")
	recent := filepath.Join(tmp, "state-recent.json")
	notState := filepath.Join(tmp, "other.json")

	for _, f := range []string{old1, old2, recent, notState} {
		os.WriteFile(f, []byte("{}"), 0o600)
	}

	// Set old files to 48 hours ago
	oldTime := now.Add(-48 * time.Hour)
	os.Chtimes(old1, oldTime, oldTime)
	os.Chtimes(old2, oldTime, oldTime)

	// Set recent file to 12 hours ago
	recentTime := now.Add(-12 * time.Hour)
	os.Chtimes(recent, recentTime, recentTime)

	// notState is recent but not a state file
	os.Chtimes(notState, recentTime, recentTime)

	PruneStates(tmp, maxAge, now)

	// old1 and old2 should be removed
	if _, err := os.Stat(old1); !os.IsNotExist(err) {
		t.Error("old1 should have been pruned")
	}
	if _, err := os.Stat(old2); !os.IsNotExist(err) {
		t.Error("old2 should have been pruned")
	}

	// recent and notState should remain
	if _, err := os.Stat(recent); err != nil {
		t.Error("recent should not have been pruned")
	}
	if _, err := os.Stat(notState); err != nil {
		t.Error("notState should not have been pruned (not a state file)")
	}
}

func TestStateDirCreation(t *testing.T) {
	tmp := t.TempDir()
	nestedDir := filepath.Join(tmp, "nested", "state")

	state := State{
		"/test": Record{Allowed: true, Digest: "test", VerifiedAt: time.Now()},
	}

	err := SaveState(nestedDir, "test", state)
	if err != nil {
		t.Fatalf("SaveState should create directory, got error: %v", err)
	}

	// Verify directory was created with 0o700
	info, err := os.Stat(nestedDir)
	if err != nil {
		t.Fatalf("state directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("state path is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("state directory has mode %o, want 0o700", info.Mode().Perm())
	}
}

func TestStateFilePermissions(t *testing.T) {
	tmp := t.TempDir()

	state := State{
		"/test": Record{Allowed: true, Digest: "test", VerifiedAt: time.Now()},
	}

	sessionID := "perms-test"
	err := SaveState(tmp, sessionID, state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	stateFile := filepath.Join(tmp, "state-"+sessionID+".json")
	info, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("state file not found: %v", err)
	}

	// File should be readable/writable by owner only (0o600)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file has mode %o, want 0o600", info.Mode().Perm())
	}
}

func TestStateAtomicWrite(t *testing.T) {
	tmp := t.TempDir()

	state := State{
		"/test": Record{Allowed: true, Digest: "test", VerifiedAt: time.Now()},
	}

	sessionID := "atomic-test"

	// First write
	err := SaveState(tmp, sessionID, state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Second write should atomically replace
	state["/test2"] = Record{Allowed: false, Digest: "test2", VerifiedAt: time.Now()}
	err = SaveState(tmp, sessionID, state)
	if err != nil {
		t.Fatalf("SaveState second write failed: %v", err)
	}

	// Verify no temp files left behind
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}

	// Verify state has both entries
	loaded := LoadState(tmp, sessionID)
	if len(loaded) != 2 {
		t.Errorf("loaded state has %d entries, want 2", len(loaded))
	}
}

func TestStateJSONFormat(t *testing.T) {
	tmp := t.TempDir()

	state := State{
		"/test": Record{
			Allowed:    true,
			Digest:     "abcd1234",
			VerifiedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	sessionID := "format-test"
	err := SaveState(tmp, sessionID, state)
	if err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Read raw JSON
	stateFile := filepath.Join(tmp, "state-"+sessionID+".json")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Parse as generic map to verify structure
	var raw map[string]map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	rec, ok := raw["/test"]
	if !ok {
		t.Fatal("missing /test in JSON")
	}

	if rec["allowed"] != true {
		t.Errorf("allowed = %v, want true", rec["allowed"])
	}
	if rec["digest"] != "abcd1234" {
		t.Errorf("digest = %v, want abcd1234", rec["digest"])
	}
}
