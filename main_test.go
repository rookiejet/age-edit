package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
)

func TestCheckAccess(t *testing.T) {
	// Create a temporary file to test against.
	tempFile, err := os.CreateTemp("", "test-file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	tests := []struct {
		path     string
		readOnly bool
		expectOk bool
	}{
		// File exists and is readable.
		{tempFile.Name(), true, true},
		// File does not exist in read-only mode.
		{"nonexistent-file", true, false},
		// File does not exist, not read-only mode.
		{"nonexistent-file", false, true},
	}

	for _, tt := range tests {
		_, err := checkAccess(tt.path, tt.readOnly)
		if (err == nil) != tt.expectOk {
			t.Errorf("checkAccess(%q, readOnly=%v) = %v, expected %v", tt.path, tt.readOnly, err == nil, tt.expectOk)
		}
	}
}

func TestEncryptAndDecryptToFile(t *testing.T) {
	testData := "Hello, world!\n"

	// Create a temporary file for the input.
	inputFile, err := os.CreateTemp("", "input")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputFile.Name())
	_, _ = inputFile.WriteString(testData)
	inputFile.Close()

	// Create a temporary file for the encrypted and decrypted the output.
	encryptedFile, err := os.CreateTemp("", "encrypted")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(encryptedFile.Name())

	decryptedFile, err := os.CreateTemp("", "decrypted")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(decryptedFile.Name())

	// Generate an age key pair for testing.
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	recipient := identity.Recipient()

	// Test encryption.
	err = encryptToFile(inputFile.Name(), encryptedFile.Name(), true, recipient)
	if err != nil {
		t.Errorf("encryptToFile() failed: %v", err)
	}

	// Test decryption.
	err = decryptToFile(encryptedFile.Name(), decryptedFile.Name(), identity)
	if err != nil {
		t.Errorf("decryptToFile() failed: %v", err)
	}

	// Compare decrypted content with the original.
	decryptedContent, _ := os.ReadFile(decryptedFile.Name())
	if string(decryptedContent) != testData {
		t.Errorf("Decrypted content mismatch: got %q, but expected %q", decryptedContent, testData)
	}
}

func TestGetRoot(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"file.txt.age", "file.txt"},
		{"example.age", "example"},
		{"example.odt", "example.odt"},
		{"no-ext", "no-ext"},
	}

	for _, tt := range tests {
		result := getRoot(tt.input)

		if result != tt.expected {
			t.Errorf("getRoot(%q) is %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestLoadIdentities(t *testing.T) {
	corruptedKey := "AGE-SECRET-KEY-1XXXXXXXXXX1234567890abcdefghijklmnopqrstuvwxyz"
	validKey := "AGE-SECRET-KEY-150E3TFLT765WC7X9E2Y6KAN2XA7NE4DN0XVCR4ATTFQK6GSXCGVS3KS7MS"

	tests := []struct {
		content  string
		expected int
		hasError bool
	}{
		// A single valid key.
		{validKey + "\n", 1, false},
		// A single valid key without a line feed.
		{validKey, 1, false},
		// Multiple valid keys.
		{validKey + "\n" + validKey + "\n", 2, false},
		// An obviously invalid key.
		{"invalid-key\n", 0, true},
		// A corrupted key.
		{corruptedKey + "\n", 0, true},
		// Ignore comments and blank lines.
		{"# Comment\n \n\n" + validKey + "\n", 1, false},
		// An indented comment.
		{"    # Comment\n" + validKey, 1, false},
		// An empty file.
		{"", 0, true},
	}

	for _, tt := range tests {
		tempFile, err := os.CreateTemp("", "identities")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tempFile.Name())

		_, err = tempFile.WriteString(tt.content)
		if err != nil {
			t.Fatal(err)
		}
		tempFile.Close()

		ids, recs, err := loadIdentities(tempFile.Name())

		if tt.hasError && err == nil {
			t.Errorf("loadIdentities(%q) expected error, got none", tt.content)
		}

		if !tt.hasError && len(ids) != tt.expected {
			t.Errorf("loadIdentities(%q) returned %d identities, expected %d", tt.content, len(ids), tt.expected)
		}

		if len(ids) != len(recs) {
			t.Errorf("loadIdentities(%q) returned mismatched identities and recipients", tt.content)
		}
	}
}

func createNoOpEditor(t *testing.T, tempDir string) string {
	editorPath := filepath.Join(tempDir, "noop-editor")
	if runtime.GOOS == "windows" {
		editorPath += ".exe"
	}

	editorSrc := `package main
func main() {
	// Do nothing, just exit successfully
}`

	srcFile := filepath.Join(tempDir, "editor.go")
	if err := os.WriteFile(srcFile, []byte(editorSrc), 0o600); err != nil {
		t.Fatalf("failed to write editor source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", editorPath, srcFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build no-op editor: %v", err)
	}

	return editorPath
}

func createModifyingEditor(t *testing.T, tempDir string) string {
	editorPath := filepath.Join(tempDir, "modify-editor")
	if runtime.GOOS == "windows" {
		editorPath += ".exe"
	}

	editorSrc := `package main
import (
	"os"
)
func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	err := os.WriteFile(os.Args[1], []byte("modified content\n"), 0o600)
	if err != nil {
		os.Exit(1)
	}
}`

	srcFile := filepath.Join(tempDir, "modify-editor.go")
	if err := os.WriteFile(srcFile, []byte(editorSrc), 0o600); err != nil {
		t.Fatalf("failed to write modifying editor source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", editorPath, srcFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build modifying editor: %v", err)
	}

	return editorPath
}

func TestComputeFileHash(t *testing.T) {
	// Create a temporary file for hash test.
	content := "test content for hashing"
	testFile, err := os.CreateTemp("", "hash-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(testFile.Name())

	if _, err := testFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	testFile.Close()

	// Compute hash.
	hash1, err := computeFileHash(testFile.Name())
	if err != nil {
		t.Fatalf("computeFileHash() failed: %v", err)
	}

	// Compute hash again - should be identical.
	hash2, err := computeFileHash(testFile.Name())
	if err != nil {
		t.Fatalf("computeFileHash() failed on second call: %v", err)
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("computeFileHash() returned different hashes for same file")
	}

	// Modify the file.
	if err := os.WriteFile(testFile.Name(), []byte(content+"modified"), 0o600); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	// Compute hash of modified file.
	hash3, err := computeFileHash(testFile.Name())
	if err != nil {
		t.Fatalf("computeFileHash() failed on modified file: %v", err)
	}

	if bytes.Equal(hash1, hash3) {
		t.Error("computeFileHash() returned same hash for different file contents")
	}
}

func TestEdit(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	idFile, err := os.CreateTemp("", "identities")
	if err != nil {
		t.Fatalf("failed to create temp identity file: %v", err)
	}
	defer os.Remove(idFile.Name())
	_, _ = idFile.WriteString(identity.String())
	idFile.Close()

	tests := []struct {
		name            string
		readOnly        bool
		checkFn         func(t *testing.T, tempDir string)
		expectEditError bool
	}{
		{
			name:     "read-only mode",
			readOnly: true,
			checkFn: func(t *testing.T, tempDir string) {
				files, err := os.ReadDir(tempDir)
				if err != nil {
					t.Fatalf("could not read temp dir: %v", err)
				}
				if len(files) != 1 {
					t.Fatalf("expected 1 file in temp dir, got %d", len(files))
				}
				tempFilePath := filepath.Join(tempDir, files[0].Name())
				info, err := os.Stat(tempFilePath)
				if err != nil {
					t.Fatalf("could not stat temp file: %v", err)
				}

				// The permissions should be read-only.
				perm := info.Mode().Perm()
				refPerm := os.FileMode(0o400)
				if perm != refPerm && !(runtime.GOOS == "windows" && perm&0o700 == refPerm) {
					t.Errorf("expected temp file permissions to be %o, got %o", refPerm, perm)
				}
			},
			expectEditError: false,
		},
		{
			name:     "no changes made",
			readOnly: false,
			checkFn:  nil, // Will be tested by verifying encrypted file hasn't changed.
			expectEditError: false,
		},
		{
			name:     "changes made",
			readOnly: false,
			checkFn:  nil, // Will be tested by verifying encrypted file was updated.
			expectEditError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create encrypted file with some content.
			content := "secret content"
			plainFile, err := os.CreateTemp("", "plain")
			if err != nil {
				t.Fatalf("failed to create temp plain file: %v", err)
			}
			defer os.Remove(plainFile.Name())
			if _, err := plainFile.WriteString(content); err != nil {
				t.Fatalf("failed to write to plain file: %v", err)
			}
			plainFile.Close()

			encFile, err := os.CreateTemp("", "encrypted")
			if err != nil {
				t.Fatalf("failed to create temp encrypted file: %v", err)
			}
			defer os.Remove(encFile.Name())

			if err := encryptToFile(plainFile.Name(), encFile.Name(), false, identity.Recipient()); err != nil {
				t.Fatalf("failed to encrypt file for test: %v", err)
			}

			// Get original encrypted file stats for comparison
			originalStat, err := os.Stat(encFile.Name())
			if err != nil {
				t.Fatalf("failed to stat encrypted file: %v", err)
			}

			// Create a temporary directory.
			tempDirPrefix, err := os.MkdirTemp("", "age-edit-test")
			if err != nil {
				t.Fatalf("failed to create temp dir for test: %v", err)
			}
			defer os.RemoveAll(tempDirPrefix)

			// Call edit.
			var editor string
			if tt.name == "changes made" {
				editor = createModifyingEditor(t, tempDirPrefix)
			} else {
				editor = createNoOpEditor(t, tempDirPrefix)
			}

			tempDir, err := edit(idFile.Name(), encFile.Name(), tempDirPrefix, false, editor, tt.readOnly)
			if (err != nil) != tt.expectEditError {
				t.Fatalf("edit() error = %v, expectEditError %v", err, tt.expectEditError)
			}
			if err == nil && tempDir != "" {
				defer os.RemoveAll(tempDir)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, tempDir)
			}

			if tt.name == "no changes made" {
				newStat, err := os.Stat(encFile.Name())
				if err != nil {
					t.Fatalf("failed to stat encrypted file after edit: %v", err)
				}

				// Check if modification time changed - it should not have.
				if !newStat.ModTime().Equal(originalStat.ModTime()) {
					t.Errorf("encrypted file was modified even though no changes were made")
				}
			} else if tt.name == "changes made" {
				newStat, err := os.Stat(encFile.Name())
				if err != nil {
					t.Fatalf("failed to stat encrypted file after edit: %v", err)
				}

				// Check if modification time changed - it should have.
				if newStat.ModTime().Equal(originalStat.ModTime()) {
					t.Errorf("encrypted file was not modified even though changes were made")
				}

				// Check if content has changed.
				decryptedFile, err := os.CreateTemp("", "decrypted-check")
				if err != nil {
					t.Fatalf("failed to create temp file for decryption check: %v", err)
				}
				defer os.Remove(decryptedFile.Name())

				if err := decryptToFile(encFile.Name(), decryptedFile.Name(), identity); err != nil {
					t.Fatalf("failed to decrypt file for content check: %v", err)
				}

				newContent, err := os.ReadFile(decryptedFile.Name())
				if err != nil {
					t.Fatalf("failed to read decrypted file: %v", err)
				}

				if string(newContent) != "modified content\n" {
					t.Errorf("expected 'modified content\\n', got %q", string(newContent))
				}
			}
		})
	}
}
