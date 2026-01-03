package main

import (
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/joshuaschlichting/loadmaster/internal/acme"
)

type S3Config struct {
	BucketName string `json:"bucketName"`
	Endpoint   string `json:"endpoint"`
	Region     string `json:"region"`
}

type AppConfig struct {
	Email        string   `json:"email"`
	S3           S3Config `json:"s3"`
	LocalCertDir string   `json:"localCertDir"`
	CAAuthority  string   `json:"caAuthority"`
}

type DomainsConfig struct {
	Domains [][]string `json:"domains"`
}

func loadAppConfig(filename string) (*AppConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config AppConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func loadDomainsConfig(filename string) (*DomainsConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config DomainsConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func initSelfSignedTLSCerts(domains *DomainsConfig) error {
	for _, domainGroup := range domains.Domains {
		log.Printf("Processing certificate for domains: %v", domainGroup)

		err := acme.GenerateSelfSignedTLSCert(domainGroup)
		if err != nil {
			log.Printf("Error obtaining/renewing certificate for %v: %v", domainGroup, err)
		} else {
			log.Printf("Successfully processed certificate for %v", domainGroup)
		}
	}
	return nil
}

func getS3ParamsFromConfig(config *AppConfig) acme.NewS3ACMEStorageParams {
	return acme.NewS3ACMEStorageParams{
		BucketName:   config.S3.BucketName,
		ContactEmail: config.Email,
		LocalCertDir: config.LocalCertDir,
		CAAuthority:  config.CAAuthority,
	}
}

var defaultConfigDir string = filepath.Join(os.Getenv("HOME"), ".loadmaster")

func main() {

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug, // allow debug
	}))
	slog.SetDefault(logger)
	var domainsFile string
	var configFile string
	flag.StringVar(&domainsFile, "domains", filepath.Join(defaultConfigDir, "domains.json"), "Path to domains configuration file")
	flag.StringVar(&configFile, "config", filepath.Join(defaultConfigDir, "config.json"), "Path to application configuration file")
	flag.Parse()
	log.Printf("Starting certificate manager")
	log.Printf("Domains file: %s", domainsFile)
	log.Printf("Config file: %s", configFile)

	if _, err := os.Stat(domainsFile); os.IsNotExist(err) {

		log.Println(domainsFile, "does not exist. Creating...")
		// Create parent directory if it doesn't exist
		dir := filepath.Dir(domainsFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating parent directory: %v", err)
		}

		file, err := os.Create(domainsFile)
		if err != nil {
			log.Fatalf("Error creating domains file: %v", err)
		}
		// Write default domains config
		defaultDomains := DomainsConfig{
			Domains: [][]string{
				{"example.com", "www.example.com"},
			},
		}
		defaultDomainsWithEmail := map[string]interface{}{
			"domains": defaultDomains.Domains,
		}
		defaultDomainsJSON, err := json.MarshalIndent(defaultDomainsWithEmail, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling default domains config: %v", err)
		}
		_, err = file.Write(defaultDomainsJSON)
		if err != nil {
			log.Fatalf("Error writing default domains config: %v", err)
		}
		log.Println("Default domains config created.")
		defer file.Close()
		log.Println("Please edit", domainsFile, "and restart the application.")
		os.Exit(1)
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {

		log.Println(configFile, "does not exist. Creating...")
		// Create parent directory if it doesn't exist
		dir := filepath.Dir(configFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating parent directory: %v", err)
		}

		file, err := os.Create(configFile)
		if err != nil {
			log.Fatalf("Error creating config file: %v", err)
		}

		// Write default application config with local and S3 storage settings
		defaultConfig := AppConfig{
			Email:        "admin@example.com",
			LocalCertDir: filepath.Join(defaultConfigDir, "certs"),
			CAAuthority:  "https://acme-staging-v02.api.letsencrypt.org/directory",
			S3: S3Config{
				BucketName: "my-certificates",
				Endpoint:   "",
				Region:     "us-east-1",
			},
		}

		defaultConfigJSON, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling default application config: %v", err)
		}
		_, err = file.Write(defaultConfigJSON)
		if err != nil {
			log.Fatalf("Error writing default application config: %v", err)
		}
		log.Println("Default application config created.")
		defer file.Close()
		log.Println("Please edit", configFile, "and restart the application.")
		os.Exit(1)
	}

	appConfig, err := loadAppConfig(configFile)
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

	domains, err := loadDomainsConfig(domainsFile)
	if err != nil {
		log.Printf("Error loading domains: %v", err)
	} else {
		log.Printf("Loaded %d domain groups", len(domains.Domains))
		err = initSelfSignedTLSCerts(domains)
		if err != nil {
			log.Printf("Error maintaining certificates: %v", err)
		}
	}

	for domainGroup := range domains.Domains {
		storage.UpdateTLS(domains.Domains[domainGroup])
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

				domains, err := loadDomainsConfig(domainsFile)
				if err != nil {
					log.Printf("Error loading domains: %v", err)
				} else {
					log.Printf("Loaded %d domain groups", len(domains.Domains))

					for domainGroup := range domains.Domains {
						storage.UpdateTLS(domains.Domains[domainGroup])
					}

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
