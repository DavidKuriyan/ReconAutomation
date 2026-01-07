package scanner

import (
	"log"
	"os/exec"
	"strings"
)

// Scanner handles the execution of reconnaissance tools
type Scanner struct {
	// Config?
}

func New() *Scanner {
	return &Scanner{}
}

// RunSubdomainDiscovery executes subfinder
func (s *Scanner) RunSubdomainDiscovery(target string) ([]string, error) {
	log.Printf("[Scanner] Starting subdomain discovery for %s", target)
	
	// Create a temporary file to store results
	// In a production environment, we might stream stdout directly
	
	// Command: subfinder -d target -silent
	cmd := exec.Command("subfinder", "-d", target, "-silent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Subfinder failed: %v", err)
		return nil, err
	}

	// Parse output
	var results []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}
	
	log.Printf("[Scanner] Found %d subdomains", len(results))
	return results, nil
}

// RunPortScan simulates running naabu/nmap
func (s *Scanner) RunPortScan(target string) ([]string, error) {
	log.Printf("[Scanner] Starting port scan for %s", target)
	
	cmd := exec.Command("naabu", "-host", target, "-silent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Naabu failed: %v", err)
		return nil, err
	}

	var results []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			results = append(results, strings.TrimSpace(line))
		}
	}

	return results, nil
}
