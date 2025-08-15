package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/carlmjohnson/crockford"
	flag "github.com/cornfeedhobo/pflag"
)

const (
	defaultTempDirPrefix = "/dev/shm/"
	filePerm             = 0o600
	fileReadOnlyPerm     = 0o400
	tempDirPerm          = 0o700
	version              = "0.9.0"
)

type encryptError struct {
	err      error
	tempFile string
}

func (e *encryptError) Error() string {
	return fmt.Sprintf("encryption failed: %v", e.err)
}

// Handle both armored and binary age files transparently.
func wrapDecrypt(r io.Reader, identities ...age.Identity) (io.Reader, error) {
	buffer := make([]byte, len(armor.Header))

	// Check if the input starts with an armor header.
	n, err := io.ReadFull(r, buffer)
	if err != nil && !errors.Is(err, io.EOF) && n < len(armor.Header) {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	armored := string(buffer[:n]) == armor.Header
	r = io.MultiReader(bytes.NewReader(buffer[:n]), r)

	if armored {
		return age.Decrypt(armor.NewReader(r), identities...)
	}

	return age.Decrypt(r, identities...)
}

func withFiles(inputPath, outputPath string, action func(in io.Reader, out io.Writer) error) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	return action(in, out)
}

func decryptToFile(inputPath, outputPath string, identities ...age.Identity) error {
	return withFiles(inputPath, outputPath, func(in io.Reader, out io.Writer) error {
		d, err := wrapDecrypt(in, identities...)
		if err != nil {
			return err
		}

		_, err = io.Copy(out, d)
		return err
	})
}

func encryptToFile(inputPath, outputPath string, armored bool, recipients ...age.Recipient) error {
	return withFiles(inputPath, outputPath, func(in io.Reader, out io.Writer) error {
		var w io.Writer = out

		if armored {
			armorWriter := armor.NewWriter(out)
			defer armorWriter.Close()

			w = armorWriter
		}

		encryptWriter, err := age.Encrypt(w, recipients...)
		if err != nil {
			return err
		}
		defer encryptWriter.Close()

		_, err = io.Copy(encryptWriter, in)
		return err
	})
}

func randomID() string {
	buf := make([]byte, 0, 8)
	buf = crockford.AppendRandom(crockford.Lower, buf)
	return string(buf)
}

func computeFileHash(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func getRoot(path string) string {
	return strings.TrimSuffix(path, ".age")
}

func checkAccess(path string, readOnly bool) (bool, error) {
	_, err := os.Stat(path)

	if err != nil && os.IsNotExist(err) {
		if readOnly {
			return false, fmt.Errorf("%q doesn't exist; won't attempt to create it in read-only mode", path)
		}

		return false, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return true, fmt.Errorf("can't read from file %q", path)
	}
	f.Close()

	// If not in read-only mode, try to open for writing.
	// We don't want writing to fail later, after the user edits the file.
	if !readOnly {
		f, err := os.OpenFile(path, os.O_RDWR, 0600)

		if err != nil {
			return true, fmt.Errorf("can't write to file %q", path)
		}

		f.Close()
	}

	return true, nil
}

func loadIdentities(path string) ([]age.Identity, []age.Recipient, error) {
	var identities []age.Identity
	var recipients []age.Recipient

	identityData, err := os.ReadFile(path)
	if err != nil {
		return identities, recipients, fmt.Errorf("failed to read identities file: %v", err)
	}

	identityCount := 0
	for _, line := range strings.Split(string(identityData), "\n") {
		line := strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		identityCount++

		identity, err := age.ParseX25519Identity(line)
		if err != nil {
			return identities, recipients, fmt.Errorf("failed to parse private key number %d: %v", identityCount, err)
		}

		identities = append(identities, identity)
		recipients = append(recipients, identity.Recipient())
	}

	if len(identities) == 0 {
		return identities, recipients, fmt.Errorf("no identities found in file")
	}

	return identities, recipients, nil
}

func parseEditorCommand(editorCmd string) (string, []string) {
	var parts []string
	var current strings.Builder
	inQuote := false
	var quoteChar rune
	escaped := false

	for _, r := range editorCmd {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' && !inQuote {
			escaped = true
			continue
		}

		if !inQuote && (r == '"' || r == '\'') {
			inQuote = true
			quoteChar = r
			continue
		}

		if inQuote && r == quoteChar {
			inQuote = false
			continue
		}

		if !inQuote && (r == ' ' || r == '\t') {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	if len(parts) == 0 {
		return "", nil
	}

	args := parts[1:]
	if len(args) == 0 {
		args = nil
	}

	return parts[0], args
}

func edit(idsPath, encPath, tempDirPrefix string, armor bool, editor string, readOnly bool) (tempDir string, err error) {
	var exists bool
	exists, err = checkAccess(encPath, readOnly)
	if err != nil {
		return
	}

	identities, recipients, err := loadIdentities(idsPath)
	if err != nil {
		return
	}

	currentUser, err := user.Current()
	if err != nil {
		return
	}

	subdir := randomID()
	tempDir = filepath.Join(tempDirPrefix, "age-edit-"+currentUser.Username, subdir)
	err = os.MkdirAll(tempDir, tempDirPerm)
	if err != nil {
		return
	}

	rootname := getRoot(encPath)
	tempFile := filepath.Join(tempDir, filepath.Base(rootname))

	if exists {
		if err = decryptToFile(encPath, tempFile, identities...); err != nil {
			return
		}
	} else {
		file, createErr := os.Create(tempFile)
		if createErr != nil {
			err = createErr
			return
		}
		file.Close()
	}

	if readOnly {
		if err = os.Chmod(tempFile, fileReadOnlyPerm); err != nil {
			return
		}
	}

	var originalHash []byte
	if !readOnly {
		originalHash, err = computeFileHash(tempFile)
		if err != nil {
			return
		}
	}

	editorName, editorArgs := parseEditorCommand(editor)

	args := append(editorArgs, tempFile)

	cmd := exec.Command(editorName, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return
	}

	if !readOnly {
		modifiedHash, hashErr := computeFileHash(tempFile)
		if hashErr != nil {
			err = hashErr
			return
		}

		if !bytes.Equal(originalHash, modifiedHash) {
			if err = encryptToFile(tempFile, encPath, armor, recipients...); err != nil {
				err = &encryptError{err: err, tempFile: tempFile}
				return
			}
		}
	}

	return
}

func cli() int {
	if err := lockMemory(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}

	armored := flag.BoolP(
		"armor",
		"a",
		false,
		"write an armored age file",
	)
	editorFlag := flag.StringP(
		"editor",
		"e",
		"",
		"command to use for editing the encrypted file",
	)
	readOnly := flag.BoolP(
		"read-only",
		"r",
		false,
		"make the temporary file read-only and discard all changes",
	)
	showVersion := flag.BoolP(
		"version",
		"V",
		false,
		"report the program version and exit",
	)
	tempDirPrefix := flag.StringP(
		"temp-dir",
		"t",
		defaultTempDirPrefix,
		"temporary directory prefix",
	)
	warn := flag.IntP(
		"warn",
		"w",
		0,
		"warn if the editor exits after less than a number seconds (zero to disable)",
	)

	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			"Usage: %s [options] identities encrypted-file\n\nOptions:\n",
			filepath.Base(os.Args[0]),
		)

		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Println(version)

		return 0
	}

	if flag.NArg() < 2 {
		flag.Usage()

		return 2
	}

	editor := *editorFlag
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}

	keyPath := flag.Arg(0)
	filename := flag.Arg(1)

	start := int(time.Now().Unix())

	tempDir, err := edit(keyPath, filename, *tempDirPrefix, *armored, editor, *readOnly)
	if tempDir != "" {
		// Remove the "age-edit-"+username directory if empty
		// after removing the temporary file and the random subdirectory.
		defer os.Remove(filepath.Dir(tempDir))
		defer os.RemoveAll(tempDir)
	}

	if *warn > 0 && int(time.Now().Unix())-start <= int(*warn) {
		fmt.Fprintf(
			os.Stderr,
			"Warning: editor exited after less than %d second(s)\n",
			*warn,
		)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)

		if encErr, ok := err.(*encryptError); ok {
			fmt.Fprintf(
				os.Stderr,
				"Press <enter> to delete temporary file %q\n",
				encErr.tempFile,
			)
			_, _ = fmt.Scanln()
		}

		return 1
	}

	return 0
}

func main() {
	os.Exit(cli())
}
