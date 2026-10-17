package config

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		domain  string
		want    bool
	}{
		{"exact match", "example.org", "example.org", true},
		{"matching ignores case", "Example.ORG", "example.org", true},
		{"exact pattern skips subdomains", "example.org", "www.example.org", false},
		{"wildcard matches subdomain", "*.example.org", "www.example.org", true},
		{"wildcard matches deep subdomain", "*.example.org", "a.b.example.org", true},
		{"wildcard pattern covers its apex", "*.example.org", "example.org", true},
		{"apex pattern covers wildcard certificate", "example.org", "*.example.org", true},
		{"apex pattern skips other zones", "example.org", "other.org", false},
		{"wildcard pattern skips other zones", "*.example.org", "www.other.com", false},
		{"catch all matches everything", "*", "anything.example.com", true},
		{"question mark matches one character", "web-?.example.org", "web-1.example.org", true},
		{"question mark rejects longer labels", "web-?.example.org", "web-12.example.org", false},
		{"character class matches", "server[0-9].example.org", "server7.example.org", true},
		{"character class rejects other characters", "server[0-9].example.org", "serverx.example.org", false},
		{"malformed pattern never matches", "[bad", "example.org", false},
		{"empty pattern never matches", "", "example.org", false},
		{"empty domain never matches", "example.org", "", false},
		{"pattern and domain are trimmed", " *.example.org ", " APP.Example.Org ", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MatchDomain(tc.pattern, tc.domain))
		})
	}
}

func TestMatchGlobs(t *testing.T) {
	patterns := []string{"example.org", "*.cdn.example.net"}

	assert.True(t, MatchGlobs(patterns, "example.org"), "literal pattern should match")
	assert.True(t, MatchGlobs(patterns, "img.cdn.example.net"), "wildcard pattern should match")
	assert.False(t, MatchGlobs(patterns, "other.com"), "no pattern should match")
	assert.False(t, MatchGlobs(nil, "example.org"), "no patterns should match nothing")
}

func TestValidateGlobPattern(t *testing.T) {
	assert.NoError(t, ValidateGlobPattern("*.example.org"))
	assert.NoError(t, ValidateGlobPattern("*"))
	assert.NoError(t, ValidateGlobPattern("web-?.example.org"))
	assert.NoError(t, ValidateGlobPattern("server[0-9].example.org"))

	assert.Error(t, ValidateGlobPattern(""))
	assert.Error(t, ValidateGlobPattern("   "))
	assert.Error(t, ValidateGlobPattern("["))
	assert.Error(t, ValidateGlobPattern("foo["))
	assert.Error(t, ValidateGlobPattern("x\\"))
}

func TestSelectDNSProvider(t *testing.T) {
	providers := []DNSProviderConfig{
		{Name: "cloudflare"}, // Default entry without match.
		{Name: "arvancloud", Match: []string{"example.org"}},       // Apex pattern for one zone.
		{Name: "cloudflare", Match: []string{"*.cdn.example.org"}}, // Wildcard pattern for another.
	}

	assert.Equal(t, -1, SelectDNSProvider(nil, "example.org"), "no provider configured")

	assert.Equal(t, 0, SelectDNSProvider(providers, "example.com"), "unmatched domains use the default entry")
	assert.Equal(t, 0, SelectDNSProvider(providers, "www.example.org"), "apex pattern does not cover subdomains")
	assert.Equal(t, 1, SelectDNSProvider(providers, "example.org"), "apex pattern matches its zone")
	assert.Equal(t, 1, SelectDNSProvider(providers, "*.example.org"), "wildcard certificate resolves via its apex")
	assert.Equal(t, 2, SelectDNSProvider(providers, "img.cdn.example.org"), "wildcard pattern matches the zone")
	assert.Equal(t, 2, SelectDNSProvider(providers, "cdn.example.org"), "wildcard pattern covers its apex challenge")
}
