package acme

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/fmotalleb/edged/config"
)

const (
	testShortTimeout  = 30 * time.Second
	testShortInterval = time.Second
	testLongTimeout   = 2 * time.Minute
	testLongInterval  = 5 * time.Second
)

// fakeDNSProvider records the challenges routed to it.
type fakeDNSProvider struct {
	presented []string
	cleaned   []string
	timeout   time.Duration
	interval  time.Duration
}

func (f *fakeDNSProvider) Present(domain, _, _ string) error {
	f.presented = append(f.presented, domain)
	return nil
}

func (f *fakeDNSProvider) CleanUp(domain, _, _ string) error {
	f.cleaned = append(f.cleaned, domain)
	return nil
}

func (f *fakeDNSProvider) Timeout() (time.Duration, time.Duration) {
	return f.timeout, f.interval
}

// plainDNSProvider does not implement challenge.ProviderTimeout.
type plainDNSProvider struct{}

func (p *plainDNSProvider) Present(_, _, _ string) error { return nil }

func (p *plainDNSProvider) CleanUp(_, _, _ string) error { return nil }

func TestRoutedDNSProviderRoutesPerDomain(t *testing.T) {
	defaultProvider := &fakeDNSProvider{timeout: testShortTimeout, interval: testShortInterval}
	zoneProvider := &fakeDNSProvider{timeout: testLongTimeout, interval: testLongInterval}

	router := newRoutedDNSProvider(
		[]config.DNSProviderConfig{
			{Name: "cloudflare"},
			{Name: "arvancloud", Match: []string{"example.org", "*.example.net"}},
		},
		[]challenge.Provider{defaultProvider, zoneProvider},
	)

	// Matched domains are presented through their own provider...
	assert.NoError(t, router.Present("example.org", "tok", "key"))
	assert.NoError(t, router.Present("a.example.net", "tok", "key"))
	// ...case-insensitively...
	assert.NoError(t, router.Present("EXAMPLE.ORG", "tok", "key"))
	// ...while unmatched domains fall back to the first entry.
	assert.NoError(t, router.Present("other.com", "tok", "key"))
	assert.NoError(t, router.Present("deep.a.example.net", "tok", "key"))

	assert.Equal(t, []string{"other.com"}, defaultProvider.presented)
	assert.Equal(t,
		[]string{"example.org", "a.example.net", "EXAMPLE.ORG", "deep.a.example.net"},
		zoneProvider.presented)

	// CleanUp follows the same routing.
	assert.NoError(t, router.CleanUp("a.example.net", "tok", "key"))
	assert.NoError(t, router.CleanUp("other.com", "tok", "key"))
	assert.Equal(t, []string{"a.example.net"}, zoneProvider.cleaned)
	assert.Equal(t, []string{"other.com"}, defaultProvider.cleaned)
}

func TestRoutedDNSProviderWithoutProviders(t *testing.T) {
	router := newRoutedDNSProvider(nil, nil)

	err := router.Present("example.org", "tok", "key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no DNS provider is configured")

	err = router.CleanUp("example.org", "tok", "key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no DNS provider is configured")
}

func TestRoutedDNSProviderTimeoutAggregation(t *testing.T) {
	fast := &fakeDNSProvider{timeout: testShortTimeout, interval: testShortInterval}
	slow := &fakeDNSProvider{timeout: testLongTimeout, interval: testLongInterval}

	router := newRoutedDNSProvider(
		[]config.DNSProviderConfig{
			{Name: "cloudflare"},
			{Name: "arvancloud", Match: []string{"*"}},
		},
		[]challenge.Provider{fast, slow},
	)

	timeout, interval := router.Timeout()
	assert.Equal(t, testLongTimeout, timeout, "the longest propagation timeout wins")
	assert.Equal(t, testShortInterval, interval, "the shortest polling interval wins")
}

func TestRoutedDNSProviderTimeoutDefaults(t *testing.T) {
	router := newRoutedDNSProvider(
		[]config.DNSProviderConfig{{Name: "cloudflare"}},
		[]challenge.Provider{&plainDNSProvider{}},
	)

	timeout, interval := router.Timeout()
	assert.Equal(t, dns01.DefaultPropagationTimeout, timeout)
	assert.Equal(t, dns01.DefaultPollingInterval, interval)
}
