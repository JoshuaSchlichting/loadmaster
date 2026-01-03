package acme

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"
)

var loadmasterHomeDir = path.Join(os.Getenv("HOME"), ".loadmaster")
var localCertDir = filepath.Join(loadmasterHomeDir, "certs")

// MaxRemainingDaysBeforeCertExpiry is the maximum number of days before a certificate expires that it should be renewed.
var MaxRemainingDaysBeforeCertExpiry = 60

func init() {
	if MaxRemainingDaysBeforeCertExpiry < 60 {
		slog.Warn("YOU ARE IN DANGER OF HITTING LET'S ENCRYPT's RATE LIMITS. PLEASE ADJUST maxRemainingDaysBeforeCertExpiry", "maxRemainingDaysBeforeCertExpiry", MaxRemainingDaysBeforeCertExpiry)
	} else {
		slog.Debug(fmt.Sprintf("maxRemainingDaysBeforeCertExpiry set to %d", MaxRemainingDaysBeforeCertExpiry))
	}
}

func removeExisting(domain string) {
	filepath := filepath.Join(localCertDir, domain)
	err := os.RemoveAll(filepath)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed to remove %s: %v", filepath, err))
	}
}

// parseCertificate parses a PEM-encoded certificate.
func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate: cert bytes == nil")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM certificate. block type is not 'CERTIFICATE'")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	return cert, nil
}

// certExpiresSoon checks the certificate in the given folder and renews it if it is expired or about to expire.
func certExpiresSoon(certData []byte, maxRemainingDaysBeforeCertExpiry int) (bool, error) {

	// Parse the certificate
	cert, err := parseCertificate(certData)
	if err != nil {
		return true, fmt.Errorf("error parsing certificate: %v", err)
	}

	// Get the expiration date of the certificate
	expirationDate := cert.NotAfter
	// Calculate the remaining days until expiration
	remainingDays := int(time.Until(expirationDate).Hours() / 24)
	slog.Debug("Certificate expiry date",
		"expirationDate", expirationDate,
		"remainingDays", remainingDays,
		"maxRemainingDaysBeforeCertExpiry", maxRemainingDaysBeforeCertExpiry,
	)

	// if maxRemainingDaysBeforeCertExpiry days or less until expiration, renew
	if remainingDays <= maxRemainingDaysBeforeCertExpiry {
		fmt.Println("Only " + strconv.Itoa(remainingDays) + " days until TLS cert expiration.")

		return true, nil
	}
	slog.Debug(fmt.Sprintf("Certificate is still valid for %d days. Days remaining until renewal: %d", remainingDays, remainingDays-maxRemainingDaysBeforeCertExpiry))

	return false, nil
}

func GetLocalCertFilenames(domain string) (string, string) {
	return path.Join(localCertDir, domain, "cert.pem"), path.Join(localCertDir, domain, "privkey.pem")
}

func writeCertToFilesToDisk(domain string, certData, privateKeyData []byte) error {
	certFolder := filepath.Join(localCertDir, domain)
	certFilename, privateKeyFilename := GetLocalCertFilenames(domain)

	slog.Debug("Writing certificate to disk")
	if err := os.MkdirAll(certFolder, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(certFilename, certData, 0644); err != nil {
		return fmt.Errorf("failed to write certificate to disk: %w", err)
	}

	if err := os.WriteFile(privateKeyFilename, privateKeyData, 0644); err != nil {
		return fmt.Errorf("failed to write private key to disk: %w", err)
	}
	slog.Debug("Certificate written to disk", "certFilename", certFilename, "privateKeyFilename", privateKeyFilename)
	return nil
}

// GenerateSelfSignedTLSCert sets locally generated and signed certificates for the given domains.
func GenerateSelfSignedTLSCert(domainGroup []string) error {
	for _, domainGroupRoot := range domainGroup {
		domainRoot := domainGroupRoot
		certData, privateKeyData, err := generateSelfSignedCert(domainRoot)
		if err != nil {
			return fmt.Errorf("error generating self-signed certificate: %v", err)
		}
		err = writeCertToFilesToDisk(domainRoot, certData, privateKeyData)
		if err != nil {
			return fmt.Errorf("error writing certificate to disk: %v", err)
		}
	}
	return nil
}
