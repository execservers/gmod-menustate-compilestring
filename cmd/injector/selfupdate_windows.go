//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Stage, verify, atomically swap the running EXE where Windows allows it,
// and spawn the new version. The old version is retained as a backup.
func replaceAndRestart(newBinary []byte) error {
	ownPath, err := os.Executable()
	if err != nil {
		return err
	}
	ownPath, err = filepath.Abs(ownPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(ownPath)
	temp, err := os.CreateTemp(dir, ".gmod-update-*.exe")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(newBinary); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	backup := ownPath + ".old-" + strconv.Itoa(os.Getpid())
	if err := os.Rename(ownPath, backup); err != nil {
		return fmt.Errorf("cannot rename running EXE: %w", err)
	}
	if err := os.Rename(temp.Name(), ownPath); err != nil {
		recoverErr := os.Rename(backup, ownPath)
		return errors.Join(err, recoverErr)
	}
	proc, err := os.StartProcess(ownPath, os.Args, &os.ProcAttr{
		Dir:   dir,
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		// Restore old executable if launch failed.
		failed := ownPath + ".failed-" + strconv.Itoa(os.Getpid())
		if e := os.Rename(ownPath, failed); e != nil {
			return errors.Join(err, e)
		}
		return errors.Join(err, os.Rename(backup, ownPath))
	}
	return proc.Release()
}
