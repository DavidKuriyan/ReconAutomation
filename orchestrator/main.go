package main

import (
	"log"
	"os"
	"time"

	"aether-recon/internal/bus"
	"aether-recon/internal/scanner"
)

func main() {
	log.Println("Starting Aether-Recon Orchestrator...")

	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost:6379"
	}

	client, err := bus.NewRedisClient(redisHost)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer client.Close()

	log.Println("Connected to Redis event bus")

	// Initialize Scanner
	scanEngine := scanner.New()

	// Subscribe to start scan events
	err = client.Subscribe("target:start", func(payload string) {
		log.Printf("Received target:start event for: %s", payload)
		
		go func() {
			// 1. Subdomain Discovery
			subdomains, err := scanEngine.RunSubdomainDiscovery(payload)
			if err != nil {
				log.Printf("Error discovering subdomains: %v", err)
				return
			}

			// 2. Publish events for each subdomain (Fan-out)
			for _, sub := range subdomains {
				log.Printf("Publishing scan:subdomain_found -> %s", sub)
				client.Publish("scan:subdomain_found", sub)
			}
		}()
	})
	if err != nil {
		log.Fatalf("Failed to subscribe to target:start: %v", err)
	}

	// Keep alive
	select {}
}
