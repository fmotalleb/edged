package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/arvancloud"
)

const arvancloudAPIBaseURL = "https://napi.arvancloud.ir"

// arvancloudFixProvider wraps the lego arvancloud DNS provider, adding a pre-cleanup
// step in Present() that removes any stale TXT records that would otherwise cause a
// "DNS Record Data is duplicate" 422 error from the ArvanCloud API.
type arvancloudFixProvider struct {
	inner      *arvancloud.DNSProvider
	apiKey     string
	httpClient *http.Client
}

// compile-time interface checks
var _ challenge.Provider = (*arvancloudFixProvider)(nil)
var _ challenge.ProviderTimeout = (*arvancloudFixProvider)(nil)

// newArvancloudFixProvider creates a new arvancloudFixProvider that wraps the given
// lego arvancloud provider. httpClient is used for the extra API calls; if nil,
// http.DefaultClient is used.
func newArvancloudFixProvider(inner *arvancloud.DNSProvider, apiKey string, httpClient *http.Client) *arvancloudFixProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &arvancloudFixProvider{
		inner:      inner,
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

// Present implements challenge.Provider. It first cleans up any existing TXT records
// that would collide with the new challenge record, then delegates to the inner provider.
func (f *arvancloudFixProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	// Best-effort pre-cleanup of stale records that would cause a duplicate error.
	if authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN); err == nil {
		authZone = dns01.UnFqdn(authZone)
		if subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, authZone); err == nil {
			// Use a short-lived context so a hung ArvanCloud API doesn't block the ACME flow.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = f.deleteRecordsByName(cleanupCtx, authZone, subDomain)
		}
	}

	return f.inner.Present(domain, token, keyAuth)
}

// CleanUp delegates to the inner provider.
func (f *arvancloudFixProvider) CleanUp(domain, token, keyAuth string) error {
	return f.inner.CleanUp(domain, token, keyAuth)
}

// Timeout delegates to the inner provider.
func (f *arvancloudFixProvider) Timeout() (timeout, interval time.Duration) {
	return f.inner.Timeout()
}

// ---------------------------------------------------------------------------
// Minimal ArvanCloud API helpers – only enough to list & delete TXT records
// ---------------------------------------------------------------------------

// arvancloudRecord is a minimal DNS record as returned by the ArvanCloud list API.
type arvancloudRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// deleteRecordsByName lists TXT records in zone whose name matches (or would
// match after underscore removal) and deletes them.
func (f *arvancloudFixProvider) deleteRecordsByName(ctx context.Context, zone, name string) error {
	records, err := f.listRecords(ctx, zone, name)
	if err != nil {
		return fmt.Errorf("listing records: %w", err)
	}

	nameWithoutUnderscores := strings.ReplaceAll(name, "_", "")

	for _, rec := range records {
		if rec.Type != "txt" {
			continue
		}
		// Match either the exact name or the name with underscores stripped.
		if rec.Name != name && rec.Name != nameWithoutUnderscores {
			continue
		}
		if err := f.deleteRecord(ctx, zone, rec.ID); err != nil {
			// Continue best-effort so one failure doesn't block the whole cleanup.
			continue
		}
	}
	return nil
}

// listRecords calls the ArvanCloud DNS records list endpoint.
func (f *arvancloudFixProvider) listRecords(ctx context.Context, zone, search string) ([]arvancloudRecord, error) {
	endpoint, err := url.Parse(arvancloudAPIBaseURL)
	if err != nil {
		return nil, err
	}
	endpoint = endpoint.JoinPath("cdn", "4.0", "domains", zone, "dns-records")

	if search != "" {
		q := endpoint.Query()
		q.Set("search", search)
		endpoint.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", f.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []arvancloudRecord `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Data, nil
}

// deleteRecord calls the ArvanCloud DNS record delete endpoint.
func (f *arvancloudFixProvider) deleteRecord(ctx context.Context, zone, id string) error {
	endpoint, err := url.Parse(arvancloudAPIBaseURL)
	if err != nil {
		return err
	}
	endpoint = endpoint.JoinPath("cdn", "4.0", "domains", zone, "dns-records", id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", f.apiKey)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status: %d, body: %s", resp.StatusCode, string(body))
	}
	return nil
}
