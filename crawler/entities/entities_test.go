package entities

import (
	"strings"
	"testing"
)

func TestRejectsInvalidCVEYear(t *testing.T) {
	text := "Exploited via CVE-1850-99999 and the real one, CVE-2024-3094."
	result := Extract(text)
	if len(result.CVEs) != 1 || result.CVEs[0] != "CVE-2024-3094" {
		t.Fatalf("expected only valid-year CVE, got: %v", result.CVEs)
	}
}

func TestRejectsKnownNoiseHash(t *testing.T) {
	text := "Empty file hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Real malware: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	result := Extract(text)
	for _, h := range result.Hashes {
		if strings.EqualFold(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
			t.Fatal("known noise hash (sha256 of empty string) should be filtered")
		}
	}
}

func TestRejectsInvalidTLD(t *testing.T) {
	text := "Visit example.notarealTLD or the legit evil-c2-server.com"
	result := Extract(text)
	for _, d := range result.Domains {
		if d == "example.notarealtld" {
			t.Fatal("invalid TLD should be rejected")
		}
	}
	found := false
	for _, d := range result.Domains {
		if d == "evil-c2-server.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("valid domain should be kept")
	}
}
