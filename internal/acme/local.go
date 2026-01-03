package acme

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

type LocalACMEStorage struct {
	contactEmail string
	caAuthority  string
}

func NewLocalACMEStorage(email, caAuthority string) *LocalACMEStorage {
	return &LocalACMEStorage{
		contactEmail: email,
		caAuthority:  caAuthority,
	}
}

func (s *LocalACMEStorage) LoadUser(emailAddress string) (DomainUser, error) {
	filename := fmt.Sprintf("%s.json", emailAddress)
	userJson, err := os.ReadFile(filename)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error reading user file: %s", err)
	}
	var user DomainUser
	err = json.Unmarshal(userJson, &user)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error unmarshalling user: %s", err)
	}

	// load the private key
	keyFilename := fmt.Sprintf("%s.pem", emailAddress)
	pemBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error reading private key file: %s", err)
	}
	// Decode the PEM data
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return DomainUser{}, fmt.Errorf("failed to decode PEM block containing private key")
	}
	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return DomainUser{}, err
	}

	// Assert the type to *ecdsa.PrivateKey
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return DomainUser{}, fmt.Errorf("key is not of type *ecdsa.PrivateKey")
	}

	user.key = privateKey

	registration, err := s.LoadRegistration()
	if err != nil {
		slog.Warn("error loading registration", "error", err)
	} else {
		user.Registration = registration
	}

	return user, nil
}

func (s *LocalACMEStorage) SaveUser(user DomainUser) error {
	slog.Debug("saving ACME user", "user", user, "registration", user.Registration)

	userJson, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("error marshalling user: %s", err)
	}
	filename := filepath.Join(loadmasterHomeDir, fmt.Sprintf("%s.json", user.Email))
	slog.Debug("saving user to file", "user", userJson)
	err = os.WriteFile(filename, userJson, 0644)
	if err != nil {
		return fmt.Errorf("error writing user to file: %s", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(user.key)
	if err != nil {
		return err
	}

	// Create a pem.Block with the private key
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	// Encode the private key into PEM format
	privateKeyPem := pem.EncodeToMemory(privateKeyBlock)
	keyFilename := fmt.Sprintf("%s.pem", user.Email)
	err = os.WriteFile(keyFilename, privateKeyPem, 0600)
	if err != nil {
		return fmt.Errorf("error writing private key to file: %s", err)
	}

	return nil
}

func (s *LocalACMEStorage) SaveRegistration(reg *registration.Resource) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	return os.WriteFile("registration.json", data, 0600)
}

// Load the registration information from a file
func (s *LocalACMEStorage) LoadRegistration() (*registration.Resource, error) {
	data, err := os.ReadFile("registration.json")
	if err != nil {
		return nil, err
	}
	var reg registration.Resource
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

// DownloadCert find the domainRoot's folder within localCertDir and return cert/key from inside.
// Expected filenames:
// - fullchain.pem or cert.pem for certificate
// - privkey.pem or key.pem for private key
// If these do not exist, return an error.
func (s *LocalACMEStorage) DownloadCert(domainRoot string) (certData []byte, keyData []byte, err error) {

	certDir := filepath.Join(localCertDir, domainRoot)

	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	certData, err = os.ReadFile(certPath)
	if err != nil || len(certData) == 0 {
		return nil, nil, fmt.Errorf("certificate not found in %s", certDir)
	}

	keyData, err = os.ReadFile(keyPath)
	if err != nil || len(keyData) == 0 {
		return nil, nil, fmt.Errorf("private key not found in %s", certDir)
	}
	if len(keyData) == 0 {
		return nil, nil, fmt.Errorf("private key not found in %s", certDir)
	}

	return certData, keyData, nil
}

func (s *LocalACMEStorage) SaveCert(domainRoot string, certData, privateKeyData []byte) error {
	return fmt.Errorf("'saveCerts' not implemented in LocalACMEStorage")
}

// UpdateTLS checks the TLS certificates for the given domains and renews them if they are expired or about to expire.
func (s *LocalACMEStorage) UpdateTLS(domainGroup []string) error {

	slog.Debug("Starting certificate check for ", "domains", domainGroup)

	domainRoot := domainGroup[0]

	certData, privateKeyData, err := s.DownloadCert(domainRoot)
	if err != nil {
		slog.Error("error while downloading certificates from S3", "error", err)
	}
	certData, privateKeyData, err = renewACMECertificate(renewACMECertificateParams{
		email:          s.contactEmail,
		domains:        domainGroup,
		caAuthorityURL: s.caAuthority,
		s:              s,
	})
	slog.Debug("Checking certificate expiry", "domains", domainGroup)

	if len(certData) == 0 || len(privateKeyData) == 0 {
		slog.Warn("certData or privateKeyData is nil or empty after renewal process. Creating a self-signed cert...", "certData", certData, "privateKeyData", privateKeyData)
		certData, privateKeyData, err = generateSelfSignedCert(domainRoot)
		if err != nil {
			return fmt.Errorf("error generating self-signed certificate (as a result of errors renewing certificate via ACME protocol): %v", err)
		}

	}
	removeExisting(domainRoot)
	err = writeCertToFilesToDisk(domainRoot, certData, privateKeyData)
	if err != nil {
		return fmt.Errorf("error writing certificate to disk: %v", err)
	}

	return nil
}
