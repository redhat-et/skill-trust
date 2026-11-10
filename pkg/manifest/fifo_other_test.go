//go:build !unix

package manifest

import "errors"

// mkfifo is unsupported on non-Unix platforms; tests skip when it fails.
func mkfifo(path string) error {
	return errors.New("mkfifo unsupported on this platform")
}
