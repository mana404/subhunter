package main

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"github.com/yourusername/subhunter/pkg/output"
	"github.com/yourusername/subhunter/pkg/resolver"
	"github.com/yourusername/subhunter/pkg/sources"
)

const banner = `
 ____        _     _   _             _
/ ___| _   _| |__ | | | |_   _ _ __ | |_ ___ _ __
\___ \| | | | '_ \| |_| | | | | '_ \| __/ _ \ '__|
 ___) | |_| | |_) |  _  | |_| | | | | ||  __/ |
|____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_|

    Bug Bounty Subdomain Enumeration Tool v1.0
    By: github.com/yourusername/subhunter
`

func main() {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	fmt.Println(cyan(banner))

	app := &cli.App{
		Name:  "subhunter",
		Usage: "Fast subdomain enumeration tool for bug bounty hunters",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Aliases:  []string{"d"},
				Usage:    "Target domain (e.g. hackerone.com)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output file to save results",
			},
			&cli.BoolFlag{
				Name:    "silent",
				Aliases: []string{"s"},
				Usage:   "Silent mode - only print subdomains",
			},
			&cli.BoolFlag{
				Name:    "resolve",
				Aliases: []string{"r"},
				Usage:   "Resolve subdomains to check if alive",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output in JSON format",
			},
			&cli.BoolFlag{
				Name:  "all",
				Usage: "Use all sources (slower but more results)",
			},
			&cli.StringFlag{
				Name:    "github-token",
				Aliases: []string{"gt"},
				Usage:   "GitHub personal access token (for GitHub source)",
				EnvVars: []string{"GITHUB_TOKEN"},
			},
			&cli.StringFlag{
				Name:    "chaos-key",
				Aliases: []string{"ck"},
				Usage:   "Chaos API key (for Chaos source)",
				EnvVars: []string{"CHAOS_KEY"},
			},
			&cli.IntFlag{
				Name:    "threads",
				Aliases: []string{"t"},
				Usage:   "Number of concurrent threads",
				Value:   50,
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Verbose mode - show source info",
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		color.Red("[-] Error: %v", err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	domain := c.String("domain")
	silent := c.Bool("silent")
	verbose := c.Bool("verbose")
	resolve := c.Bool("resolve")
	jsonOut := c.Bool("json")
	outFile := c.String("output")
	threads := c.Int("threads")
	useAll := c.Bool("all")

	cfg := &sources.Config{
		Domain:      domain,
		GitHubToken: c.String("github-token"),
		ChaosKey:    c.String("chaos-key"),
		Threads:     threads,
		UseAll:      useAll,
		Silent:      silent,
		Verbose:     verbose,
	}

	if !silent {
		color.Cyan("[*] Target    : %s", domain)
		color.Cyan("[*] Threads   : %d", threads)
		color.Cyan("[*] Resolve   : %v", resolve)
		color.Cyan("[*] Sources   : %s", cfg.ActiveSources())
		fmt.Println()
	}

	// Run all sources concurrently
	runner := sources.NewRunner(cfg)
	results := runner.Run()

	// Optionally resolve
	if resolve {
		if !silent {
			color.Yellow("[*] Resolving subdomains...")
		}
		results = resolver.FilterAlive(results, threads)
	}

	// Output
	printer := output.NewPrinter(output.Config{
		Silent:  silent,
		JSON:    jsonOut,
		Verbose: verbose,
		OutFile: outFile,
	})

	count, err := printer.Print(results)
	if err != nil {
		return err
	}

	if !silent {
		fmt.Println()
		color.Green("[+] Total unique subdomains found: %d", count)
		if outFile != "" {
			color.Green("[+] Results saved to: %s", outFile)
		}
	}

	return nil
}
