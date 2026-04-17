package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// DefaultFolder is loaded from the OUTPUT_FOLDER env var, or falls back to a local output/ dir.
func DefaultFolder() string {
	if v := os.Getenv("OUTPUT_FOLDER"); v != "" {
		return v
	}
	return "output"
}

// NewFile creates a timestamped output file in the output folder.
// name is used as the base of the filename (e.g. hostname or filename).
// Returns the file and its full path.
func NewFile(folder, name string) (*os.File, string, error) {
	if err := os.MkdirAll(folder, 0755); err != nil {
		return nil, "", fmt.Errorf("cannot create output folder: %w", err)
	}

	clean := sanitize(name)
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s-%s.txt", clean, timestamp)
	fullPath := filepath.Join(folder, filename)

	f, err := os.Create(fullPath)
	if err != nil {
		return nil, "", fmt.Errorf("cannot create output file: %w", err)
	}
	return f, fullPath, nil
}

// MultiWriter returns an io.Writer that writes to both stdout and w.
func MultiWriter(w io.Writer) io.Writer {
	return io.MultiWriter(os.Stdout, w)
}

var invalidChars = regexp.MustCompile(`[^a-zA-Z0-9.\-_]`)

func sanitize(s string) string {
	return invalidChars.ReplaceAllString(s, "_")
}
