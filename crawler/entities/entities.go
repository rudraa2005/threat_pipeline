package entities

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

var (
	ipv4Candidate   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	sha256Pattern   = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	sha1Pattern     = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	md5Pattern      = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	cveCandidate    = regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`)
	emailPattern    = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)
	domainCandidate = regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b`)
)

var knownNoiseHashes = map[string]bool{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         true,
	"d41d8cd98f00b204e9800998ecf8427e":                                 true,
}

type Indicators struct {
	IPs     []string
	Hashes  []string
	CVEs    []string
	Emails  []string
	Domains []string
}

func Extract(text string) Indicators {
	return Indicators{
		IPs:     validIPs(ipv4Candidate.FindAllString(text, -1)),
		Hashes:  validHashes(text),
		CVEs:    validCVEs(cveCandidate.FindAllString(text, -1)),
		Emails:  dedup(emailPattern.FindAllString(text, -1)),
		Domains: validDomains(domainCandidate.FindAllString(text, -1)),
	}
}

func validIPs(candidates []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, c := range candidates {
		if net.ParseIP(c) != nil && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func validHashes(text string) []string {
	var all []string
	all = append(all, sha256Pattern.FindAllString(text, -1)...)
	all = append(all, sha1Pattern.FindAllString(text, -1)...)
	all = append(all, md5Pattern.FindAllString(text, -1)...)

	seen := make(map[string]bool)
	var out []string
	for _, h := range all {
		lower := strings.ToLower(h)
		if knownNoiseHashes[lower] {
			continue
		}
		if !seen[lower] {
			seen[lower] = true
			out = append(out, h)
		}
	}
	return out
}

func validCVEs(candidates []string) []string {
	seen := make(map[string]bool)
	var out []string
	currentYear := time.Now().Year()

	for _, c := range candidates {
		parts := strings.Split(c, "-")
		if len(parts) != 3 {
			continue
		}

		year, err := strconv.Atoi(parts[1])
		if err != nil || year < 1999 || year > currentYear {
			continue
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func validDomains(candidates []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range candidates {
		lower := strings.ToLower(d)
		if _, icann := publicsuffix.PublicSuffix(lower); !icann {
			continue
		}
		if !seen[lower] {
			seen[lower] = true
			out = append(out, lower)
		}
	}
	return out
}

func dedup(items []string) []string {
	seen := make(map[string]bool)
	var out []string

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func (i Indicators) Flatten() []string {
	var out []string
	out = append(out, i.IPs...)
	out = append(out, i.CVEs...)
	out = append(out, i.Domains...)
	out = append(out, i.Emails...)
	out = append(out, i.Hashes...)
	return out
}
