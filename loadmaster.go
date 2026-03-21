package loadmaster

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/joshuaschlichting/loadmaster/internal/acme"
	"github.com/joshuaschlichting/loadmaster/internal/config"
)

// Config holds the runtime configuration for LoadMaster.
type Config struct {
	// DataDir is the base data directory containing configuration, domains, certs, and ACME user data.
	DataDir string
	// DomainsFile is the path to the domains configuration file.
	DomainsFile string
	// ConfigFile is the path to the application configuration file.
	ConfigFile string
	// CertsDir is the optional path to the certificates directory.
	CertsDir string
	// HTTPChallengePort is the port on which the HTTP‑01 challenge server will listen.
	HTTPChallengePort int
}

// LoadMaster orchestrates loading configuration, updating certificates, and watching for changes.
type LoadMaster struct {
	cfg        Config
	appConfig  *config.AppConfig
	domains    *config.DomainsConfig
	storage    acme.ACMEStorage
	watcher    *fsnotify.Watcher
	logger     *slog.Logger
}

// New creates a new LoadMaster instance from the supplied configuration.
// It performs initial loading of configuration files and sets up storage.
func New(cfg Config) (*LoadMaster, error) {
	lm := &LoadMaster{
		cfg:    cfg,
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	// Resolve defaults
	if cfg.ConfigFile == "" {
		cfg.ConfigFile = filepath.Join(cfg.DataDir, "config.json")
	}
	if cfg.DomainsFile == "" {
		cfg.DomainsFile = filepath.Join(cfg.DataDir, "domains.json")
	}

	appConfig, err := config.LoadAppConfig(cfg.ConfigFile, cfg.DomainsFile)
	if err != nil {
		return nil, err
	}
	lm.appConfig = appConfig

	if cfg.CertsDir != "" {
		appConfig.LocalCertDir = cfg.CertsDir
	} else {
		appConfig.LocalCertDir = filepath.Join(cfg.DataDir, "certs")
	}

	// Ensure certificate directory exists
	if _, err := os.Stat(appConfig.LocalCertDir); os.IsNotExist(err) {
		if err := os.MkdirAll(appConfig.LocalCertDir, 0755); err != nil {
			return nil, err
		}
	}

	// Storage selection
	if appConfig.S3.BucketName != "" {
		s3Params := acme.NewS3ACMEStorageParams{
			BucketName:   appConfig.S3.BucketName,
			ContactEmail: appConfig.Email,
			LocalCertDir: appConfig.LocalCertDir,
			CAAuthority:  appConfig.CAAuthority,
		}
		storage, err := acme.NewS3ACMEStorage(s3Params)
		if err != nil {
			lm.logger.Warn("failed to create S3 storage, falling back to local", "error", err)
			storage = acme.NewLocalACMEStorage(appConfig.Email, appConfig.CAAuthority)
		}
		lm.storage = storage
	} else {
		lm.storage = acme.NewLocalACMEStorage(appConfig.Email, appConfig.CAAuthority)
	}

	// Load domains
	domains, err := config.LoadDomainsConfig(cfg.DomainsFile)
	if err != nil {
		return nil, err
	}
	lm.domains = domains

	// Set challenge port
	acme.HTTPChallengePort = cfg.HTTPChallengePort

	return lm, nil
}

// Start initiates the certificate update loop and file watcher.
// It blocks until the process is terminated.
func (lm *LoadMaster) Start() error {
	// Initial update
	if err := lm.updateAll(); err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	lm.watcher = watcher
	defer watcher.Close()

	if err := watcher.Add(lm.cfg.DomainsFile); err != nil {
		return err
	}

	lm.logger.Info("watching domains file for changes", "file", lm.cfg.DomainsFile)

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				lm.logger.Info("domains file modified, reloading", "file", event.Name)
				time.Sleep(100 * time.Millisecond) // small debounce
				if err := lm.reloadDomains(); err != nil {
					lm.logger.Error("failed to reload domains", "error", err)
				}
			}
		case <-ticker.C:
			lm.logger.Info("periodic certificate refresh")
			if err := lm.updateAll(); err != nil {
				lm.logger.Error("periodic update failed", "error", err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			lm.logger.Error("watcher error", "error", err)
		}
	}
}

// updateAll updates all domain groups in storage.
func (lm *LoadMaster) updateAll() error {
	for _, group := range lm.domains.Domains {
		if err := lm.storage.UpdateTLS(group); err != nil {
			lm.logger.Warn("updateTLS failed", "domains", group, "error", err)
		}
	}
	return nil
}

// reloadDomains reloads the domains configuration from disk
// and triggers an update for each group.
func (lm *LoadMaster) reloadDomains() error {
	domains, err := config.LoadDomainsConfig(lm.cfg.DomainsFile)
	if err != nil {
		return err
	}
	lm.domains = domains
	return lm.updateAll()
}
