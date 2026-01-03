package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

var DefaultConfigDir string = filepath.Join(os.Getenv("HOME"), ".loadmaster")

type S3Config struct {
	BucketName string `json:"bucketName"`
	Endpoint   string `json:"endpoint"`
	Region     string `json:"region"`
}

type AppConfig struct {
	Email        string   `json:"email"`
	S3           S3Config `json:"s3"`
	LocalCertDir string   `json:"-"`
	CAAuthority  string   `json:"caAuthority"`
}

type DomainsConfig struct {
	Domains [][]string `json:"domains"`
}

func LoadAppConfig(configFilename, domainsFilename string) (*AppConfig, error) {

	if _, err := os.Stat(domainsFilename); os.IsNotExist(err) {

		log.Println(domainsFilename, "does not exist. Creating...")
		// Create parent directory if it doesn't exist
		dir := filepath.Dir(domainsFilename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating parent directory: %v", err)
		}

		file, err := os.Create(domainsFilename)
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
		defer func() { _ = file.Close() }()
		log.Println("Please edit", domainsFilename, "and restart the application.")
		os.Exit(1)
	}

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {

		log.Println(configFilename, "does not exist. Creating...")
		dir := filepath.Dir(configFilename)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error creating parent directory: %v", err)
		}

		file, err := os.Create(configFilename)
		if err != nil {
			log.Fatalf("Error creating config file: %v", err)
		}

		// Write default application config with local and S3 storage settings
		defaultConfig := AppConfig{
			Email: "admin@example.com",

			CAAuthority: "https://acme-staging-v02.api.letsencrypt.org/directory",
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
		defer func() { _ = file.Close() }()
		log.Println("Please edit", configFilename, "and restart the application.")
		os.Exit(1)
	}

	data, err := os.ReadFile(configFilename)
	if err != nil {
		return nil, err
	}

	var config AppConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	if config.LocalCertDir == "" {
		config.LocalCertDir = filepath.Join(DefaultConfigDir, "certs")
	}
	return &config, nil
}

func LoadDomainsConfig(filename string) (*DomainsConfig, error) {
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
