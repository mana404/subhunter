package sources

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

func get(url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "subhunter/1.0 (bug-bounty-tool)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ─── crt.sh ──────────────────────────────────────────────────────────────────

type CrtSHSource struct{}

func (s *CrtSHSource) Name() string { return "crt.sh" }

func (s *CrtSHSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)
	for _, e := range entries {
		for _, sub := range strings.Split(e.NameValue, "\n") {
			sub = strings.TrimPrefix(strings.TrimSpace(sub), "*.")
			if !seen[sub] && sub != "" {
				seen[sub] = true
				results = append(results, Result{Subdomain: sub, Source: s.Name()})
			}
		}
	}
	return results, nil
}

// ─── HackerTarget ────────────────────────────────────────────────────────────

type HackerTargetSource struct{}

func (s *HackerTargetSource) Name() string { return "hackertarget" }

func (s *HackerTargetSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var results []Result
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			sub := strings.TrimSpace(parts[0])
			ip := ""
			if len(parts) >= 2 {
				ip = strings.TrimSpace(parts[1])
			}
			if sub != "" && strings.Contains(sub, cfg.Domain) {
				results = append(results, Result{Subdomain: sub, Source: s.Name(), IP: ip})
			}
		}
	}
	return results, nil
}

// ─── ThreatCrowd ─────────────────────────────────────────────────────────────

type ThreatCrowdSource struct{}

func (s *ThreatCrowdSource) Name() string { return "threatcrowd" }

func (s *ThreatCrowdSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range resp.Subdomains {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			results = append(results, Result{Subdomain: sub, Source: s.Name()})
		}
	}
	return results, nil
}

// ─── RapidDNS ────────────────────────────────────────────────────────────────

type RapidDNSSource struct{}

func (s *RapidDNSSource) Name() string { return "rapiddns" }

func (s *RapidDNSSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, cfg.Domain) && !strings.Contains(line, "<") {
			sub := strings.Fields(line)[0]
			if !seen[sub] {
				seen[sub] = true
				results = append(results, Result{Subdomain: sub, Source: s.Name()})
			}
		}
	}
	return results, nil
}

// ─── DNSBuffer ───────────────────────────────────────────────────────────────

type DNSBufferSource struct{}

func (s *DNSBufferSource) Name() string { return "dnsbuffer" }

func (s *DNSBufferSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://dnsbuffer.com/?query=%s", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var results []Result
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, "."+cfg.Domain) || line == cfg.Domain {
			results = append(results, Result{Subdomain: line, Source: s.Name()})
		}
	}
	return results, nil
}

// ─── URLScan ─────────────────────────────────────────────────────────────────

type UrlScanSource struct{}

func (s *UrlScanSource) Name() string { return "urlscan.io" }

func (s *UrlScanSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=200", cfg.Domain)
	data, err := get(url, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)
	for _, r := range resp.Results {
		sub := strings.TrimSpace(r.Page.Domain)
		if sub != "" && !seen[sub] {
			seen[sub] = true
			results = append(results, Result{Subdomain: sub, Source: s.Name()})
		}
	}
	return results, nil
}

// ─── AlienVault OTX ──────────────────────────────────────────────────────────

type AlienVaultSource struct{}

func (s *AlienVaultSource) Name() string { return "alienvault" }

func (s *AlienVaultSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var results []Result
	seen := make(map[string]bool)
	for _, r := range resp.PassiveDNS {
		sub := strings.TrimSpace(r.Hostname)
		if sub != "" && !seen[sub] {
			seen[sub] = true
			results = append(results, Result{Subdomain: sub, Source: s.Name()})
		}
	}
	return results, nil
}

// ─── Anubis ──────────────────────────────────────────────────────────────────

type AnubisSource struct{}

func (s *AnubisSource) Name() string { return "anubis" }

func (s *AnubisSource) Enumerate(cfg *Config) ([]Result, error) {
	url := fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", cfg.Domain)
	data, err := get(url, nil)
	if err != nil {
		return nil, err
	}

	var subs []string
	if err := json.Unmarshal(data, &subs); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range subs {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			results = append(results, Result{Subdomain: sub, Source: s.Name()})
		}
	}
	return results, nil
}

// ─── GitHub (needs token) ────────────────────────────────────────────────────

type GitHubSource struct{}

func (s *GitHubSource) Name() string { return "github" }

func (s *GitHubSource) Enumerate(cfg *Config) ([]Result, error) {
	if cfg.GitHubToken == "" {
		return nil, fmt.Errorf("GitHub token required, use --github-token or set GITHUB_TOKEN env")
	}

	dorks := []string{
		fmt.Sprintf("%s in:file", cfg.Domain),
		fmt.Sprintf("subdomain %s in:file", cfg.Domain),
		fmt.Sprintf("hostname %s in:file", cfg.Domain),
	}

	seen := make(map[string]bool)
	var results []Result

	for _, dork := range dorks {
		url := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100",
			strings.ReplaceAll(dork, " ", "+"))

		data, err := get(url, map[string]string{
			"Authorization": "token " + cfg.GitHubToken,
			"Accept":        "application/vnd.github.v3+json",
		})
		if err != nil {
			continue
		}

		var resp struct {
			Items []struct {
				HTMLURL string `json:"html_url"`
			} `json:"items"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			continue
		}

		// Extract domain patterns from URLs found in code
		for _, item := range resp.Items {
			sub := extractSubdomain(item.HTMLURL, cfg.Domain)
			if sub != "" && !seen[sub] {
				seen[sub] = true
				results = append(results, Result{Subdomain: sub, Source: s.Name()})
			}
		}

		// Rate limit: GitHub allows 30 search requests/min for auth
		time.Sleep(2 * time.Second)
	}

	return results, nil
}

// ─── Chaos (needs API key) ───────────────────────────────────────────────────

type ChaosSource struct{}

func (s *ChaosSource) Name() string { return "chaos" }

func (s *ChaosSource) Enumerate(cfg *Config) ([]Result, error) {
	if cfg.ChaosKey == "" {
		return nil, fmt.Errorf("Chaos API key required, use --chaos-key or set CHAOS_KEY env")
	}

	url := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", cfg.Domain)
	data, err := get(url, map[string]string{
		"Authorization": cfg.ChaosKey,
	})
	if err != nil {
		return nil, err
	}

	var resp struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	var results []Result
	for _, sub := range resp.Subdomains {
		full := sub + "." + cfg.Domain
		results = append(results, Result{Subdomain: full, Source: s.Name()})
	}
	return results, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func extractSubdomain(content, domain string) string {
	// Simple heuristic to pull a subdomain from a URL
	if idx := strings.Index(content, domain); idx > 0 {
		start := idx
		for start > 0 && (content[start-1] == '.' || isAlphaNum(content[start-1]) || content[start-1] == '-') {
			start--
		}
		end := idx + len(domain)
		candidate := content[start:end]
		if strings.HasSuffix(candidate, domain) {
			return candidate
		}
	}
	return ""
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
