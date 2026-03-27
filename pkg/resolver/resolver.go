package resolver

import (
	"net"
	"sync"

	"github.com/fatih/color"
	"github.com/yourusername/subhunter/pkg/sources"
)

var defaultResolvers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"1.0.0.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

// FilterAlive resolves each subdomain and returns only the live ones
func FilterAlive(results []sources.Result, threads int) []sources.Result {
	if threads <= 0 {
		threads = 50
	}

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		alive []sources.Result
	)

	sem := make(chan struct{}, threads)

	for _, res := range results {
		wg.Add(1)
		go func(r sources.Result) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ip, ok := resolve(r.Subdomain)
			if ok {
				r.IP = ip
				r.Alive = true
				color.Green("[ALIVE] %s → %s", r.Subdomain, ip)
				mu.Lock()
				alive = append(alive, r)
				mu.Unlock()
			}
		}(res)
	}

	wg.Wait()
	return alive
}

func resolve(domain string) (string, bool) {
	addrs, err := net.LookupHost(domain)
	if err != nil || len(addrs) == 0 {
		return "", false
	}
	return addrs[0], true
}