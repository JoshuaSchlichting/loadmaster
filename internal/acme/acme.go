package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"log/slog"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"

	// TODO Implement TLS-ALPN-01 challenge
	// "github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const CAAuthorityLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
const CAAuthorityLetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"

var HTTPChallengePort = 5002

type ACMEStorage interface {
	SaveCert(domainRoot string, cert, privateKey []byte) error
	DownloadCert(domainRoot string) ([]byte, []byte, error)
	LoadUser(emailAddress string) (DomainUser, error)
	SaveUser(user DomainUser) error
	SaveRegistration(reg *registration.Resource) error
	LoadRegistration() (*registration.Resource, error)
	UpdateTLS(domainGroup []string) error
}

type resource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"-"`
	Certificate       []byte `json:"-"`
	IssuerCertificate []byte `json:"-"`
	CSR               []byte `json:"-"`
}

func createNewACMEUser(emailAddress string) (DomainUser, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error generating private key: %s", err)
	}

	return NewDomainUser(emailAddress, privateKey), nil
}

func getUser(domainUserEmail string, storage ACMEStorage) (DomainUser, error) {
	var user DomainUser
	var err error

	user, err = storage.LoadUser(domainUserEmail)
	if err != nil {
		slog.Warn("error loading ACME user. Creating new user...", "error", err)

		user, err = createNewACMEUser(domainUserEmail)
		if err != nil {
			return DomainUser{}, fmt.Errorf("error creating new ACME user: %w", err)
		}
		slog.Debug("new ACME user created", "email", domainUserEmail)
		err = storage.SaveUser(user)
		if err != nil {
			slog.Error("error saving ACME user", "error", err, "user", user.Email)
		}
	} else {
		slog.Debug("ACME user loaded", "email", user.Email, "registration", user.Registration)

	}
	return user, nil
}

func getACMERegistration(client *lego.Client, storage ACMEStorage) (*registration.Resource, error) {
	reg, err := storage.LoadRegistration()
	if err != nil {
		// If the registration information does not exist, register a new account
		slog.Error(fmt.Sprintf("error loading ACME registration from storage. Registering user with ACME server: %s", err))
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("error registering user with ACME server: %w", err)
		}
		slog.Debug("ACME registration successful", "uri", reg.URI, "account", reg.Body)
		// Save the registration information
		if err := storage.SaveRegistration(reg); err != nil {
			return nil, fmt.Errorf("error saving registration: %w", err)
		}
	}
	slog.Debug("ACME registration loaded", "uri", reg.URI, "account", reg.Body)
	return reg, nil
}

func getACMEClient(user DomainUser, caAuthority string) (*lego.Client, error) {
	config := lego.NewConfig(&user)

	config.CADirURL = caAuthority
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating lego client: %w", err)
	}
	return client, nil
}

func getRegisteredACMEClient(domainUserEmail string, storage ACMEStorage, caAuthority string) (*lego.Client, error) {
	myUser, err := getUser(domainUserEmail, storage)
	if err != nil {
		return nil, fmt.Errorf("error getting ACME user: %w", err)
	}

	client, err := getACMEClient(myUser, caAuthority)
	if err != nil {
		return nil, fmt.Errorf("error getting ACME client: %w", err)
	}

	// Proxy challenge traffic to port <HTTPChallengePort>.
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", fmt.Sprint(HTTPChallengePort)))
	if err != nil {
		return nil, fmt.Errorf("error setting http01 provider: %w", err)
	}

	// TODO: Implement TLS-ALPN-01 challenge
	// err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	// if err != nil {
	// 	return nil, fmt.Errorf("error setting tlsalpn01 provider: %w", err)
	// }

	// Load the registration information
	if myUser.Registration == nil {
		reg, err := getACMERegistration(client, storage)
		if err != nil {
			return nil, fmt.Errorf("error getting ACME registration: %w", err)
		}
		reg.Body.TermsOfServiceAgreed = true
		slog.Debug("ACME registration loaded", "uri", reg.URI, "account", reg.Body)
		myUser.Registration = reg
	}
	return client, nil
}

func generateTLS(domainUserEmail string, domains []string, acmeStorage ACMEStorage, caAuthority string) (*resource, error) {
	slog.Debug("Generating TLS certificate", "userEmail", domainUserEmail, "domains", domains)
	client, err := getRegisteredACMEClient(domainUserEmail, acmeStorage, caAuthority)
	if err != nil {
		return nil, fmt.Errorf("error getting ACME client: %w", err)
	}

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("error obtaining certificate: %w", err)
	}
	domainRoot := domains[0]
	return &resource{
		Domain:            domainRoot,
		CertURL:           certificates.CertURL,
		CertStableURL:     certificates.CertStableURL,
		PrivateKey:        certificates.PrivateKey,
		Certificate:       certificates.Certificate,
		IssuerCertificate: certificates.IssuerCertificate,
		CSR:               certificates.CSR,
	}, nil
}

type renewACMECertificateParams struct {
	email          string
	domains        []string
	caAuthorityURL string
	s              ACMEStorage
}

// renewACMECertificate renews the certificate in the given folder.
func renewACMECertificate(p renewACMECertificateParams) (certificate, privateKey []byte, err error) {
	slog.Info("Renewing ACME certificate", "domains", p.domains)

	certificateData, err := generateTLS(p.email, p.domains, p.s, p.caAuthorityURL)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating TLS certificate for %s: %v", p.domains, err)
	}

	// Parse the renewed certificate
	slog.Debug("Parsing renewed certificate")
	cert, err := parseCertificate(certificateData.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("error while parsing certificate %s", err)
	}

	// Get the expiration date of the certificate
	expirationDate := cert.NotAfter

	slog.Info("Certificate renewed successfully")
	// Calculate the remaining days until expiration
	remainingDays := int(time.Until(expirationDate).Hours() / 24)

	slog.Info("The certificate was renewed", "daysRemainingUntilExpiry", remainingDays)

	return certificateData.Certificate, certificateData.PrivateKey, nil
}
