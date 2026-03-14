package sources

import (
	"strings"
	"sync"

	"github.com/fatih/color"
)

// Config holds all source configuration
type Config struct {
	Domain      string
	GitHubToken string
	ChaosKey    string
	Threads     int
	UseAll      bool
	Silent      bool
	Verbose     bool
}

// Result represents a discovered subdomain
type Result struct {
	Subdomain string
	Source    string
	IP        string
	Alive     bool
}

// Source interface - every source implements this
type Source interface {
	Name() string
	Enumerate(cfg *Config) ([]Result, error)
}

// Runner manages all sources
type Runner struct {
	cfg     *Config
	sources []Source
}

// NewRunner creates a runner with all available sources
func NewRunner(cfg *Config) *Runner {
	allSources := []Source{
		&CrtSHSource{},
		&HackerTargetSource{},
		&ThreatCrowdSource{},
		&RapidDNSSource{},
		&DNSBufferSource{},
		&UrlScanSource{},
		&AlienVaultSource{},
		&AnubisSource{},
	}

	// Add token-required sources only if keys provided
	if cfg.GitHubToken != "" {
		allSources = append(allSources, &GitHubSource{})
	}
	if cfg.ChaosKey != "" {
		allSources = append(allSources, &ChaosSource{})
	}

	return &Runner{cfg: cfg, sources: allSources}
}

// ActiveSources returns comma-separated list of active source names
func (cfg *Config) ActiveSources() string {
	names := []string{"crt.sh", "hackertarget", "threatcrowd", "rapiddns", "dnsbuffer", "urlscan", "alienvault", "anubis"}
	if cfg.GitHubToken != "" {
		names = append(names, "github")
	}
	if cfg.ChaosKey != "" {
		names = append(names, "chaos")
	}
	return strings.Join(names, ", ")
}

// Run executes all sources concurrently and returns deduplicated results
func (r *Runner) Run() []Result {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		seen    = make(map[string]bool)
		results []Result
	)

	sem := make(chan struct{}, 5) // max 5 sources in parallel

	for _, src := range r.sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if !r.cfg.Silent && r.cfg.Verbose {
				color.Yellow("[~] Running source: %s", s.Name())
			}

			found, err := s.Enumerate(r.cfg)
			if err != nil {
				if !r.cfg.Silent && r.cfg.Verbose {
					color.Red("[-] %s error: %v", s.Name(), err)
				}
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, res := range found {
				sub := strings.ToLower(strings.TrimSpace(res.Subdomain))
				// Validate it's actually a subdomain of target
				if !strings.HasSuffix(sub, "."+r.cfg.Domain) && sub != r.cfg.Domain {
					continue
				}
				if !seen[sub] {
					seen[sub] = true
					res.Subdomain = sub
					results = append(results, res)

					if !r.cfg.Silent && !r.cfg.Verbose {
						color.White("%s", sub)
					}
				}
			}

			if !r.cfg.Silent {
				color.Green("[+] %s: found %d unique subdomains", s.Name(), len(found))
			}
		}(src)
	}

	wg.Wait()
	return results
}
