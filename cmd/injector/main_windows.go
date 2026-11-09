//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func run() error {
	bits := 32
	want64 := false
	if strconv.IntSize == 64 {
		bits = 64
		want64 = true
	}
	fmt.Printf("[MSC] Injector x%d (%s)\n", bits, buildVersion)

	dll, _ := embeddedDLL()
	var updater *githubUpdater
	var latest *releaseInfo
	if repository != "" && tlsSPKIPins != "" {
		fmt.Println("[Update] Checking GitHub Releases over pinned HTTPS...")
		u, err := newGithubUpdater(repository, tlsSPKIPins)
		if err != nil {
			fmt.Printf("[Update] Disabled: %v\n", err)
		} else {
			updater = u
			r, err := u.latest()
			if err != nil {
				fmt.Printf("[Update] Unavailable: %v\n", err)
			} else {
				latest = &r
			}
		}
	} else {
		fmt.Println("[Update] Offline mode (repository or TLS pins not configured).")
	}

	if latest != nil {
		exeName := "injector_win32.exe"
		if want64 {
			exeName = "injector_win64.exe"
		}
		if a, ok := latest.asset(exeName); ok {
			expected, err := expectedDigest(a)
			if err != nil {
				fmt.Printf("[Update] EXE digest unavailable: %v\n", err)
			} else {
				own, err := os.Executable()
				if err != nil {
					return err
				}
				current, err := os.ReadFile(own)
				if err != nil {
					return err
				}
				if digestOf(current) != expected {
					fmt.Printf("[Update] Downloading updated %s...\n", exeName)
					data, err := updater.download(a, maxEXE)
					if err == nil {
						err = validatePE(data, want64, false)
					}
					if err != nil {
						fmt.Printf("[Update] EXE update skipped: %v\n", err)
					} else if err := replaceAndRestart(data); err != nil {
						fmt.Printf("[Update] EXE replacement failed: %v\n", err)
					} else {
						fmt.Println("[Update] Relaunched updated injector.")
						return nil
					}
				} else {
					fmt.Println("[Update] Injector is current.")
				}
			}
		}
	}

	path, err := getDLL(updater, latest, dll, want64)
	if err != nil {
		// Network failures must not disable a valid embedded payload.
		if len(dll) != 0 {
			fmt.Printf("[DLL] Network update failed, using embedded DLL: %v\n", err)
			path, err = getDLL(nil, nil, dll, want64)
		}
		if err != nil {
			return err
		}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	fmt.Printf("[DLL] Verified: %s\n", filepath.Base(path))
	fmt.Printf("[Wait] Waiting for x%d gmod.exe / hl2.exe...\n", bits)

	attempted := make(map[uint32]time.Time)
	for {
		candidates, err := processes()
		if err != nil {
			return err
		}
		for _, candidate := range candidates {
			if t, ok := attempted[candidate.pid]; ok && time.Since(t) < 5*time.Second {
				continue
			}
			// Even if the process name matches, inject() enforces bitness.
			matches, err := inject(candidate.pid, path, bits)
			if err != nil {
				attempted[candidate.pid] = time.Now()
				fmt.Printf("[Wait] %s PID=%d: %v\n", candidate.name, candidate.pid, err)
				continue
			}
			if matches {
				fmt.Printf("[Load] %s PID=%d: DLL loaded successfully.\n", candidate.name, candidate.pid)
				fmt.Println("[OK] Done.")
				time.Sleep(2 * time.Second)
				return nil
			}
		}
		time.Sleep(time.Second)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
}
