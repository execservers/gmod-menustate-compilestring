package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestParsePins(t *testing.T) {
	value := sha256.Sum256([]byte("known test key"))
	pin := base64.StdEncoding.EncodeToString(value[:])
	pins, err := parsePins("api.github.com=" + pin + ";release-assets.githubusercontent.com=sha256/" + pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || !bytes.Equal(pins["api.github.com"][0], value[:]) {
		t.Fatal("incorrect pin decode")
	}
	for _, bad := range []string{"api.github.com=bad", "api.github.com=", "api.github.com=" + pin + ";api.github.com=" + pin, "*=foo"} {
		if _, err := parsePins(bad); err == nil {
			t.Fatalf("accepted invalid pin string %q", bad)
		}
	}
}

func TestReleaseDigest(t *testing.T) {
	data := []byte("sample")
	a := releaseAsset{Name: "payload.dll", Digest: "sha256:" + digestOf(data)}
	got, err := expectedDigest(a)
	if err != nil || got != digestOf(data) {
		t.Fatalf("digest: %s %v", got, err)
	}
	a.Digest = "sha256:" + strings.Repeat("0", 63) + "z"
	if _, err := expectedDigest(a); err == nil {
		t.Fatal("accepted invalid hash")
	}
}

func TestRejectInvalidRepo(t *testing.T) {
	for _, repo := range []string{"owner/name/extra", "https://github.com/owner/repo", "a/..", ""} {
		if repositoryRE.MatchString(repo) && !strings.Contains(repo, "..") {
			t.Fatalf("accepted bad repo %s", repo)
		}
	}
}
