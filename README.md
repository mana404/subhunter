# 🔍 SubHunter

> **Fast, multi-source subdomain enumeration tool written in Go — built for bug bounty hunters**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Build](https://github.com/yourusername/subhunter/actions/workflows/release.yml/badge.svg)](https://github.com/yourusername/subhunter/actions)

---

```
 ____        _     _   _             _
/ ___| _   _| |__ | | | |_   _ _ __ | |_ ___ _ __
\___ \| | | | '_ \| |_| | | | | '_ \| __/ _ \ '__|
 ___) | |_| | |_) |  _  | |_| | | | | ||  __/ |
|____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_|
```

## ✨ Features

- **8+ passive sources** — no loud scanning, stays under the radar
- **Concurrent** — all sources run in parallel (goroutines)
- **GitHub dorking** — finds subdomains in public code repositories
- **Chaos dataset** — access to ProjectDiscovery's massive pre-indexed database
- **DNS Resolution** — filter only alive subdomains
- **JSON output** — pipe-friendly for automation
- **Auto-deduplication** — no duplicate results
- **Cross-platform** — Linux, macOS, Windows binaries

## 📡 Sources

| Source | Type | API Key Needed |
|--------|------|---------------|
| crt.sh | Certificate Transparency | ❌ Free |
| HackerTarget | DNS search | ❌ Free |
| ThreatCrowd | Threat intel | ❌ Free |
| RapidDNS | DNS database | ❌ Free |
| URLScan.io | Web scanner | ❌ Free |
| AlienVault OTX | Threat intel | ❌ Free |
| Anubis | DNS database | ❌ Free |
| GitHub | Code search (OSINT) | ✅ Free token |
| Chaos (ProjectDiscovery) | Dataset | ✅ Free key |

## 📦 Installation

### Option 1 — Go Install
```bash
go install github.com/yourusername/subhunter/cmd@latest
```

### Option 2 — Download Binary
```bash
# Linux (amd64)
wget https://github.com/yourusername/subhunter/releases/latest/download/subhunter-linux-amd64
chmod +x subhunter-linux-amd64
sudo mv subhunter-linux-amd64 /usr/local/bin/subhunter
```

### Option 3 — Build from Source
```bash
git clone https://github.com/yourusername/subhunter
cd subhunter
make build
# or: go build -o subhunter ./cmd/
```

## 🚀 Usage

```bash
# Basic enumeration
subhunter -d hackerone.com

# Save to file + verbose output
subhunter -d hackerone.com -v -o subs.txt

# With GitHub token (finds more subs in code)
subhunter -d hackerone.com --github-token ghp_XXXX -o subs.txt

# With Chaos API key
subhunter -d nasa.gov --chaos-key YOUR_KEY -o subs.txt

# Resolve & filter alive subdomains only
subhunter -d hackerone.com -r -o live.txt

# JSON output (for automation/pipelines)
subhunter -d hackerone.com --json -o subs.json

# Silent mode (only subdomains, no banner)
subhunter -d hackerone.com -s | httpx -silent

# Full pipeline example
subhunter -d target.com -s | httpx -silent -o live.txt
```

## 🔧 All Flags

```
-d, --domain         Target domain (required)
-o, --output         Output file
-r, --resolve        DNS resolve to filter alive subdomains
-t, --threads        Concurrent threads (default: 50)
-v, --verbose        Show source info for each subdomain
-s, --silent         Silent mode — only print subdomains
    --json           JSON output format
    --all            Use all sources
    --github-token   GitHub PAT (or set GITHUB_TOKEN env)
    --chaos-key      Chaos API key (or set CHAOS_KEY env)
```

## 🔗 Pipeline Integration

```bash
# Combine with httpx to find live hosts
subhunter -d target.com -s | httpx -silent -o live.txt

# Combine with nuclei for vuln scanning
subhunter -d target.com -s | httpx -silent | nuclei -silent

# Pipe into nmap
subhunter -d target.com -s -r | nmap -iL - -p 80,443,8080

# Combine multiple tools output
subfinder -d target.com -silent > s1.txt
subhunter -d target.com -s >> s1.txt
cat s1.txt | sort -u | anew all_subs.txt
```

## 🌍 Environment Variables

```bash
export GITHUB_TOKEN="ghp_XXXXXXXXXXXXXXXX"
export CHAOS_KEY="XXXXXXXXXXXXXXXXXXXXXXXX"

# Now you can run without flags:
subhunter -d target.com -o subs.txt
```

## 📋 Get Free API Keys

| Service | Get Key |
|---------|---------|
| **GitHub Token** | https://github.com/settings/tokens (no special scopes needed) |
| **Chaos Key** | https://chaos.projectdiscovery.io (free signup) |

## 🔨 Development

```bash
# Run tests
make test

# Build for all platforms
make cross

# Lint
make lint
```

## 📁 Project Structure

```
subhunter/
├── cmd/
│   └── main.go            ← CLI entry point
├── pkg/
│   ├── sources/
│   │   ├── runner.go      ← Concurrent source runner
│   │   └── sources.go     ← All source implementations
│   ├── resolver/
│   │   └── resolver.go    ← DNS resolution + alive check
│   └── output/
│       └── output.go      ← Output formatting (txt/json/file)
├── .github/
│   └── workflows/
│       └── release.yml    ← Auto build + release CI
├── Makefile
├── go.mod
└── README.md
```

## ⚠️ Legal Notice

This tool is for **authorized security testing and bug bounty programs only**.  
Always stay within the defined scope. Never test without permission.

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

Made with ❤️ for the bug bounty community  
If this helped you find a bug, give it a ⭐