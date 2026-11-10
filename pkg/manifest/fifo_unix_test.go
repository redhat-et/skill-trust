//go:build unix

package manifest

import "syscall"

// mkfifo creates a FIFO at path (supported on Unix platforms).
func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o644)
}
