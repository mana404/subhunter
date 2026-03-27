package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/yourusername/subhunter/pkg/sources"
)

// Config holds output settings
type Config struct {
	Silent  bool
	JSON    bool
	Verbose bool
	OutFile string
}

// Printer handles all output formatting
type Printer struct {
	cfg Config
}

// NewPrinter creates a new Printer
func NewPrinter(cfg Config) *Printer {
	return &Printer{cfg: cfg}
}

// JSONResult is the JSON output format
type JSONResult struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source,omitempty"`
	IP        string `json:"ip,omitempty"`
	Alive     bool   `json:"alive,omitempty"`
}

// Print outputs all results and returns count of unique subdomains
func (p *Printer) Print(results []sources.Result) (int, error) {
	// Deduplicate by subdomain
	seen := make(map[string]sources.Result)
	for _, r := range results {
		sub := strings.ToLower(r.Subdomain)
		if _, exists := seen[sub]; !exists {
			seen[sub] = r
		}
	}

	// Sort alphabetically
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var lines []string

	if p.cfg.JSON {
		// JSON output
		var jsonResults []JSONResult
		for _, k := range keys {
			r := seen[k]
			jsonResults = append(jsonResults, JSONResult{
				Subdomain: r.Subdomain,
				Source:    r.Source,
				IP:        r.IP,
				Alive:     r.Alive,
			})
		}
		data, err := json.MarshalIndent(jsonResults, "", "  ")
		if err != nil {
			return 0, err
		}
		fmt.Println(string(data))
		lines = append(lines, string(data))
	} else {
		// Plain text output
		fmt.Println()
		color.Cyan("─────────────────────────────────────────")
		color.Cyan("  RESULTS")
		color.Cyan("─────────────────────────────────────────")
		for _, k := range keys {
			r := seen[k]
			if p.cfg.Verbose {
				if r.IP != "" {
					color.White("%-50s [%s] [%s]", r.Subdomain, r.Source, r.IP)
				} else {
					color.White("%-50s [%s]", r.Subdomain, r.Source)
				}
			} else {
				color.White("%s", r.Subdomain)
			}
			lines = append(lines, r.Subdomain)
		}
	}

	// Save to file if specified
	if p.cfg.OutFile != "" {
		if err := p.saveToFile(lines); err != nil {
			return 0, fmt.Errorf("failed to save file: %w", err)
		}
	}

	return len(seen), nil
}

func (p *Printer) saveToFile(lines []string) error {
	f, err := os.Create(p.cfg.OutFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range lines {
		fmt.Fprintln(f, line)
	}
	return nil
}