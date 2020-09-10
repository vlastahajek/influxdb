package fs

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// A FileExistsError is returned when an operation cannot be completed due to a
// file already existing.
type FileExistsError struct {
	path string
}

func newFileExistsError(path string) FileExistsError {
	return FileExistsError{path: path}
}

func (e FileExistsError) Error() string {
	return fmt.Sprintf("operation not allowed, file %q exists", e.path)
}

type DiskStatus struct {
	All   uint64
	Used  uint64
	Free  uint64
	Avail uint64
}

// DirSize returns total size in bytes of containing files
func DirSize(path string) (uint64, error) {
	var size uint64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += uint64(info.Size())
		}
		return err
	})
	return size, err
}

// CopyFile copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file. The file mode will be copied from the source and
// the copied data is synced/flushed to stable storage.
func CopyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return
	}

	err = out.Sync()
	if err != nil {
		return
	}

	si, err := os.Stat(src)
	if err != nil {
		return
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return
	}

	return
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
// Symlinks are ignored and skipped.
// dirFilterFunc allows filtering out directories. Returned true means skipping the dir.
// dirFilterFunc allows filtering out directories. Returned true means skipping the dir.
// fileFilterFunc allows filtering out files. Returned true means skipping the file.
func CopyDir(src string, dst string, dirRenameFunc func(path string) string, dirFilterFunc func(path string) bool, fileFilterFunc func(path string) bool) (err error) {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	if dirFilterFunc != nil && dirFilterFunc(src) {
		return
	}
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	if err == nil {
		return fmt.Errorf("destination already exists")
	}

	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		entryName := entry.Name()
		if dirRenameFunc != nil {
			entryName = dirRenameFunc(entryName)
		}
		dstPath := filepath.Join(dst, entryName)

		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath, dirRenameFunc, dirFilterFunc, fileFilterFunc)
			if err != nil {
				return
			}
		} else {
			// Skip symlinks.
			if entry.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if fileFilterFunc != nil && fileFilterFunc(src) {
				continue
			}
			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return
			}
		}
	}

	return
}

const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
)

// HumanSize formats number representing a disk space to human readable text with closest order units
func HumanSize(size uint64) string {
	switch {
	case size > GB:
		return fmt.Sprintf("%.1fGB", float64(size)/GB)
	case size > MB:
		return fmt.Sprintf("%.1fMB", float64(size)/MB)
	case size > KB:
		return fmt.Sprintf("%.1fKB", float64(size)/KB)
	default:
		return fmt.Sprintf("%dB", size)
	}
}
