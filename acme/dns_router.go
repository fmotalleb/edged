package acme

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/fmotalleb/edged/config"
)

// routedDNSProvider answers DNS-01 challenges with the provider configured
// for each challenged domain. Selection follows config.SelectDNSProvider,
// which mirrors the acme.dns_providers semantics: the first config entry
// whose match globs hit the challenged domain handles it, and domains matched
// by nobody are served by the first configured entry (the default).
//
// entries and providers are parallel slices built from the same
// acme.dns_providers list.
type routedDNSProvider struct {
	entries   []config.DNSProviderConfig
	providers []challenge.Provider
}

func newRoutedDNSProvider(entries []config.DNSProviderConfig, providers []challenge.Provider) *routedDNSProvider {
	return &routedDNSProvider{entries: entries, providers: providers}
}

// route returns the provider selected for the domain.
func (r *routedDNSProvider) route(domain string) (challenge.Provider, error) {
	idx := config.SelectDNSProvider(r.entries, strings.ToLower(strings.TrimSpace(domain)))
	if idx < 0 || idx >= len(r.providers) {
		return nil, fmt.Errorf("no DNS provider is configured for domain %q", domain)
	}
	return r.providers[idx], nil
}

// Present creates the TXT record through the provider selected for the domain.
func (r *routedDNSProvider) Present(domain, token, keyAuth string) error {
	provider, err := r.route(domain)
	if err != nil {
		return err
	}
	return provider.Present(domain, token, keyAuth)
}

// CleanUp removes the TXT record through the provider selected for the domain.
func (r *routedDNSProvider) CleanUp(domain, token, keyAuth string) error {
	provider, err := r.route(domain)
	if err != nil {
		return err
	}
	return provider.CleanUp(domain, token, keyAuth)
}

// Timeout aggregates the propagation settings of the configured providers:
// the longest propagation timeout and the shortest polling interval win, so
// every provider gets enough time to publish its TXT record. lego consults
// this once per challenge, right after Present routed the domain.
func (r *routedDNSProvider) Timeout() (time.Duration, time.Duration) {
	var timeout, interval time.Duration

	for _, p := range r.providers {
		provider, ok := p.(challenge.ProviderTimeout)
		if !ok {
			continue
		}

		providerTimeout, providerInterval := provider.Timeout()
		if providerTimeout > timeout {
			timeout = providerTimeout
		}
		if providerInterval > 0 && (interval == 0 || providerInterval < interval) {
			interval = providerInterval
		}
	}

	if timeout <= 0 {
		timeout = dns01.DefaultPropagationTimeout
	}
	if interval <= 0 {
		interval = dns01.DefaultPollingInterval
	}

	return timeout, interval
}
