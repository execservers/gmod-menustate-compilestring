package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxMetadata = 4 << 20
	maxDLL      = 64 << 20
	maxEXE      = 96 << 20
)

// These values are injected at build time, not supplied by an untrusted process.
var (
	repository   = "execservers/gmod-menustate-compilestring"
	tlsSPKIPins  = ""
	buildVersion = "dev"
)

var repositoryRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// Format: host=base64(SHA256(SPKI))[,backup];another-host=pin
// Pins are public keys, not secrets. Normal TLS CA/hostname validation stays on.
func parsePins(spec string) (map[string][][]byte, error) {
	out := make(map[string][][]byte)
	if spec == "" {
		return out, nil
	}
	for _, entry := range strings.Split(spec, ";") {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid TLS pin entry")
		}
		host := strings.ToLower(strings.TrimSpace(parts[0]))
		if host == "" || strings.ContainsAny(host, "/: *") {
			return nil, errors.New("invalid TLS pin host")
		}
		if _, exists := out[host]; exists {
			return nil, errors.New("duplicate TLS pin host")
		}
		for _, raw := range strings.Split(parts[1], ",") {
			raw = strings.TrimPrefix(strings.TrimSpace(raw), "sha256/")
			pin, err := base64.StdEncoding.DecodeString(raw)
			if err != nil || len(pin) != sha256.Size {
				return nil, fmt.Errorf("invalid SHA256 SPKI pin for %s", host)
			}
			out[host] = append(out[host], pin)
		}
	}
	return out, nil
}

func secureClient(pins map[string][][]byte) (*http.Client, error) {
	if len(pins["api.github.com"]) == 0 {
		return nil, errors.New("api.github.com SPKI pin is mandatory for network updates")
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			expected := pins[strings.ToLower(cs.ServerName)]
			if len(expected) == 0 {
				return fmt.Errorf("TLS host %q is not pinned", cs.ServerName)
			}
			// VerifiedChains is supplied only after standard CA and hostname verification.
			if len(cs.VerifiedChains) == 0 {
				return errors.New("no verified TLS chain")
			}
			for _, chain := range cs.VerifiedChains {
				for _, cert := range chain {
					actual := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
					for _, p := range expected {
						if subtle.ConstantTimeCompare(p, actual[:]) == 1 {
							return nil
						}
					}
				}
			}
			return fmt.Errorf("TLS SPKI pin mismatch for %s", cs.ServerName)
		},
	}
	return &http.Client{
		Transport: base,
		Timeout:   90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" || req.URL.Port() != "" {
				return errors.New("non-HTTPS redirect rejected")
			}
			host := strings.ToLower(req.URL.Hostname())
			if len(pins[host]) == 0 {
				return fmt.Errorf("redirect target %s has no TLS pin", host)
			}
			if host != "api.github.com" && host != "github.com" && !strings.HasSuffix(host, ".githubusercontent.com") {
				return fmt.Errorf("redirect target %s is not a GitHub host", host)
			}
			return nil
		},
	}, nil
}

type releaseAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type releaseInfo struct {
	Tag    string         `json:"tag_name"`
	Assets []releaseAsset `json:"assets"`
}

func (r *releaseInfo) asset(name string) (releaseAsset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return releaseAsset{}, false
}

type githubUpdater struct {
	http *http.Client
	repo string
}

func newGithubUpdater(repo, spec string) (*githubUpdater, error) {
	if !repositoryRE.MatchString(repo) || strings.Contains(repo, "..") {
		return nil, errors.New("update repository must have owner/name format")
	}
	pins, err := parsePins(spec)
	if err != nil {
		return nil, err
	}
	client, err := secureClient(pins)
	if err != nil {
		return nil, err
	}
	return &githubUpdater{http: client, repo: repo}, nil
}

func (g *githubUpdater) fetch(address, accept string, max int64) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() != "api.github.com" {
		return nil, errors.New("GitHub API endpoint must be HTTPS and api.github.com")
	}
	req, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "gmod-menustate-compilestring-injector/"+buildVersion)
	response, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub HTTP %d", response.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("release asset exceeds size limit")
	}
	return b, nil
}

func (g *githubUpdater) latest() (releaseInfo, error) {
	b, err := g.fetch("https://api.github.com/repos/"+g.repo+"/releases/latest", "application/vnd.github+json", maxMetadata)
	if err != nil {
		return releaseInfo{}, err
	}
	var r releaseInfo
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Tag == "" || len(r.Assets) == 0 {
		return r, errors.New("latest release has no assets")
	}
	return r, nil
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func expectedDigest(a releaseAsset) (string, error) {
	if !strings.HasPrefix(a.Digest, "sha256:") || len(a.Digest) != len("sha256:")+64 {
		return "", fmt.Errorf("release asset %s has no GitHub SHA-256 digest", a.Name)
	}
	h := strings.TrimPrefix(a.Digest, "sha256:")
	decoded, err := hex.DecodeString(h)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("invalid release digest")
	}
	return strings.ToLower(h), nil
}

func (g *githubUpdater) download(a releaseAsset, limit int64) ([]byte, error) {
	digest, err := expectedDigest(a)
	if err != nil {
		return nil, err
	}
	if a.Size <= 0 || a.Size > limit || a.ID <= 0 {
		return nil, errors.New("invalid release asset metadata")
	}
	address := "https://api.github.com/repos/" + g.repo + "/releases/assets/" + strconv.FormatInt(a.ID, 10)
	b, err := g.fetch(address, "application/octet-stream", limit)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != a.Size || !strings.EqualFold(digestOf(b), digest) {
		return nil, fmt.Errorf("SHA-256 or size mismatch for %s", a.Name)
	}
	return b, nil
}

func validatePE(b []byte, target64, dll bool) error {
	file, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("invalid PE: %w", err)
	}
	defer file.Close()
	machine := uint16(pe.IMAGE_FILE_MACHINE_I386)
	if target64 {
		machine = pe.IMAGE_FILE_MACHINE_AMD64
	}
	if file.FileHeader.Machine != machine {
		return errors.New("release asset has wrong CPU architecture")
	}
	isDLL := file.FileHeader.Characteristics&pe.IMAGE_FILE_DLL != 0
	if isDLL != dll {
		return errors.New("release asset DLL/EXE type mismatch")
	}
	return nil
}

func cacheDir() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "MenuCompileStringControl"), nil
}

func storeVerified(b []byte, filename string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	final := filepath.Join(dir, filename)
	existing, err := os.ReadFile(final)
	if err == nil && subtle.ConstantTimeCompare([]byte(digestOf(existing)), []byte(digestOf(b))) == 1 {
		return final, nil
	}
	temp, err := os.CreateTemp(dir, ".payload-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(b); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temp.Name(), final); err != nil {
		// If existing file is locked, use a hash-derived immutable alternate path.
		final = filepath.Join(dir, digestOf(b)[:24]+"-"+filename)
		if err2 := os.Rename(temp.Name(), final); err2 != nil {
			return "", err2
		}
	}
	return final, nil
}

func getDLL(g *githubUpdater, r *releaseInfo, embedded []byte, want64 bool) (string, error) {
	name := "menustate_compilestring_win32.dll"
	if want64 {
		name = "menustate_compilestring_win64.dll"
	}
	dll := embedded
	if len(dll) != 0 {
		if err := validatePE(dll, want64, true); err != nil {
			return "", fmt.Errorf("embedded DLL: %w", err)
		}
	}
	if g != nil && r != nil {
		if a, ok := r.asset(name); ok {
			expected, err := expectedDigest(a)
			if err != nil {
				return "", err
			}
			if len(dll) == 0 || digestOf(dll) != expected {
				fmt.Printf("[DLL] Downloading %s from release %s...\n", name, r.Tag)
				// Use previous verified file if present; do not trust filename alone.
				d, err := cacheDir()
				if err == nil {
					file := filepath.Join(d, "payload-"+expected[:24]+".dll")
					cached, readErr := os.ReadFile(file)
					if readErr == nil && digestOf(cached) == expected && validatePE(cached, want64, true) == nil {
						return file, nil
					}
				}
				downloaded, err := g.download(a, maxDLL)
				if err != nil {
					return "", err
				}
				if err := validatePE(downloaded, want64, true); err != nil {
					return "", err
				}
				return storeVerified(downloaded, "payload-"+expected[:24]+".dll")
			}
		} else if len(dll) == 0 {
			return "", fmt.Errorf("latest release has no %s", name)
		}
	}
	if len(dll) == 0 {
		return "", errors.New("no embedded DLL and no verified remote DLL")
	}
	return storeVerified(dll, "payload-"+digestOf(dll)[:24]+".dll")
}
