package config

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// MatchDomain reports whether the glob pattern matches the domain.
//
// Patterns use Go's path.Match glob syntax ("*" matches any run of
// characters, "?" a single one, "[...]" a character class), plus two
// domain-specific rules:
//
//   - Matching is case-insensitive and ignores surrounding whitespace.
//   - A wildcard pattern ("*.example.com") also matches its zone apex
//     ("example.com"), because DNS-01 challenges for a wildcard certificate
//     are presented on the apex, not on the wildcard name.
//   - A wildcard domain ("*.example.com") also matches patterns written
//     against its apex ("example.com").
func MatchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if pattern == "" || domain == "" {
		return false
	}

	for _, candidate := range domainCandidates(domain) {
		if matched, err := path.Match(pattern, candidate); err == nil && matched {
			return true
		}
		// A wildcard pattern covers the challenges presented for its own zone.
		if strings.HasPrefix(pattern, "*.") && pattern[2:] == candidate {
			return true
		}
	}

	return false
}

// MatchGlobs reports whether any of the glob patterns matches the domain.
func MatchGlobs(patterns []string, domain string) bool {
	for _, pattern := range patterns {
		if MatchDomain(pattern, domain) {
			return true
		}
	}
	return false
}

// ValidateGlobPattern checks that the pattern is a well-formed, non-empty
// domain glob that MatchDomain can evaluate.
func ValidateGlobPattern(pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return errors.New("pattern is empty")
	}
	// Matching against an empty name still walks the whole pattern, so any
	// syntax error in it surfaces as ErrBadPattern.
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
	}
	return nil
}

// domainCandidates returns the forms a domain appears as during a DNS-01
// challenge: its configured literal value plus, for wildcard domains, the
// zone apex that the TXT record is actually created on.
func domainCandidates(domain string) []string {
	if after, found := strings.CutPrefix(domain, "*."); found {
		return []string{domain, after}
	}
	return []string{domain}
}
