package main

import (
	"flag"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/joshuaschlichting/loadmaster/internal/acme"
	"github.com/joshuaschlichting/loadmaster/internal/config"
)

func getS3ParamsFromConfig(config *config.AppConfig) acme.NewS3ACMEStorageParams {
	return acme.NewS3ACMEStorageParams{
		BucketName:   config.S3.BucketName,
		ContactEmail: config.Email,
		LocalCertDir: config.LocalCertDir,
		CAAuthority:  config.CAAuthority,
	}
}

func main() {

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)
	var domainsFile string
	var configFile string
	flag.StringVar(&domainsFile, "domains", filepath.Join(config.DefaultConfigDir, "domains.json"), "Path to domains configuration file")
	flag.StringVar(&configFile, "config", filepath.Join(config.DefaultConfigDir, "config.json"), "Path to application configuration file")
	flag.Parse()
	log.Printf("Starting certificate manager")
	log.Printf("Domains file: %s", domainsFile)
	log.Printf("Config file: %s", configFile)

	appConfig, err := config.LoadAppConfig(configFile, domainsFile)
	if err != nil {
		log.Fatalf("Error loading application config: %v", err)
	}

	if _, err := os.Stat(appConfig.LocalCertDir); os.IsNotExist(err) {
		err := os.MkdirAll(appConfig.LocalCertDir, 0755)
		if err != nil {
			log.Fatalf("Error creating local certificate directory: %v", err)
		}
	}

	var storage acme.ACMEStorage

	if appConfig.S3.BucketName != "" {
		s3Params := getS3ParamsFromConfig(appConfig)
		storage, err = acme.NewS3ACMEStorage(s3Params)
		if err != nil {
			log.Printf("Error creating S3 storage: %v", err)
		}
	} else {
		storage = acme.NewLocalACMEStorage(appConfig.Email, appConfig.CAAuthority)
	}

	domains, err := config.LoadDomainsConfig(domainsFile)
	if err != nil {
		log.Printf("Error loading domains: %v", err)
	} else {
		log.Printf("Loaded %d domain groups", len(domains.Domains))
		// Boot behavior: retrieve certs from cache and refresh if expiring; fallback to self-signed only if cache missing.
		for domainGroup := range domains.Domains {
			updateErr := storage.UpdateTLS(domains.Domains[domainGroup])
			if updateErr != nil {
				log.Printf("UpdateTLS error for %v: %v", domains.Domains[domainGroup], updateErr)
			}
		}
	}

	// Watch for file changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(domainsFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Watching %s for changes...", domainsFile)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				log.Printf("Domains file modified: %s", event.Name)

				// Small delay to ensure file write is complete
				time.Sleep(100 * time.Millisecond)

				domains, err := config.LoadDomainsConfig(domainsFile)
				if err != nil {
					log.Printf("Error loading domains: %v", err)
				} else {
					log.Printf("Loaded %d domain groups", len(domains.Domains))

					for domainGroup := range domains.Domains {
						storage.UpdateTLS(domains.Domains[domainGroup])
					}

				}
			}
		case <-time.After(24 * time.Hour):
			log.Printf("Refreshing certificates...")
			for domainGroup := range domains.Domains {
				updateErr := storage.UpdateTLS(domains.Domains[domainGroup])
				if updateErr != nil {
					log.Printf("UpdateTLS error for %v: %v", domains.Domains[domainGroup], updateErr)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}
