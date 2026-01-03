package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-acme/lego/v4/registration"
)

var awsConfig aws.Config

func init() {
	err := logAWSProfileDetails()
	if err != nil {
		log.Println("Failed to log AWS config:", err)
	}
}

func logAWSProfileDetails() error {
	var err error
	awsConfig, err = config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("logAWSConfig() error initializing AWS config object: %v", err)
	}

	client := sts.NewFromConfig(awsConfig)

	input := &sts.GetCallerIdentityInput{}

	resp, err := client.GetCallerIdentity(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("logAWSConfig(): %v", err)
	}

	slog.Info("AWS Config", "account", *resp.Account, "user", *resp.UserId, "arn", *resp.Arn)
	return nil
}

type S3ACMEStorage struct {
	s3Client     *s3.Client
	uploader     *manager.Uploader
	downloader   *manager.Downloader
	serviceName  string
	localCertDir string
	bucketName   string
	contactEmail string
	caAuthority  string
}

type NewS3ACMEStorageParams struct {
	ServiceName  string
	LocalCertDir string
	BucketName   string
	ContactEmail string
	CAAuthority  string
}

func NewS3ACMEStorage(params NewS3ACMEStorageParams) (*S3ACMEStorage, error) {
	switch params.CAAuthority {
	case CAAuthorityLetsEncryptProduction:
		slog.Warn("Using Let's Encrypt PRODUCTION CA Authority", "CAAuthority", params.CAAuthority)
	case CAAuthorityLetsEncryptStaging:
		slog.Info("Using Let's Encrypt Staging CA Authority", "CAAuthority", params.CAAuthority)
	default:
		slog.Warn("Unknown CA Authority", "CAAuthority", params.CAAuthority)
	}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("error creating AWS config for S3ACMEStorage: %s", err)
	}
	return &S3ACMEStorage{
		s3Client:     s3.NewFromConfig(cfg),
		uploader:     manager.NewUploader(s3.NewFromConfig(cfg)),
		downloader:   manager.NewDownloader(s3.NewFromConfig(cfg)),
		serviceName:  params.ServiceName,
		localCertDir: params.LocalCertDir,
		bucketName:   params.BucketName,
		contactEmail: params.ContactEmail,
		caAuthority:  params.CAAuthority,
	}, nil
}

func (s *S3ACMEStorage) SaveCert(domainRoot string, cert, privateKey []byte) error {

	// Upload the file to S3
	_, err := s.uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(path.Join(s.serviceName, "certs", domainRoot, "cert.pem")),
		Body:   bytes.NewReader(cert),
	})
	if err != nil {
		return fmt.Errorf("error while uploading certificate files to S3: %v", err)
	}
	// Upload the file to S3
	_, err = s.uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(path.Join(s.serviceName, "certs", domainRoot, "privkey.pem")),
		Body:   bytes.NewReader(privateKey),
	})
	if err != nil {
		return fmt.Errorf("error while uploading certificate files to S3: %v", err)
	}
	slog.Debug(fmt.Sprintf("Successfully uploaded the renewed certificate to S3 for %s", domainRoot))

	return nil
}

func (s *S3ACMEStorage) DownloadCert(domainRoot string) ([]byte, []byte, error) {
	slog.Debug("Downloading certificate from S3 for " + domainRoot)

	certFolder := path.Join(s.localCertDir, domainRoot)
	// mkdir if not exists
	if _, err := os.Stat(certFolder); os.IsNotExist(err) {
		err = os.MkdirAll(certFolder, 0755)
		if err != nil {
			return nil, nil, fmt.Errorf("error while creating directory %s: %v", certFolder, err)
		}
	}
	// Download the cert.pem file from S3
	certData := make([]byte, 0)

	certS3Writer := manager.NewWriteAtBuffer(certData)
	s3Prefix := path.Join(s.serviceName, "certs", domainRoot)

	s3KeyCertPem := path.Join(s3Prefix, "cert.pem")
	slog.Debug(fmt.Sprintf("Downloading certificate from S3 for %s: %s", domainRoot, s3KeyCertPem))
	certDataSize, err := s.downloader.Download(context.TODO(), certS3Writer, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(s3KeyCertPem),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error while downloading certificate file from S3: %v", err)
	}
	slog.Debug("certificate downloaded", "s3key", s3KeyCertPem, "size", certDataSize)

	// Download the privkey.pem file from S3
	privateKeyData := make([]byte, 0)
	privateKeyS3Writer := manager.NewWriteAtBuffer(privateKeyData)

	s3KeyPrivKeyPem := path.Join(s3Prefix, "privkey.pem")
	slog.Debug(fmt.Sprintf("Downloading private key from S3 for %s: %s", domainRoot, s3KeyPrivKeyPem))
	privKeySize, err := s.downloader.Download(context.TODO(), privateKeyS3Writer, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(s3KeyPrivKeyPem),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error while downloading private key from S3: %v", err)
	}
	slog.Debug("private key downloaded", "s3key", s3KeyPrivKeyPem, "size", privKeySize)
	slog.Debug(fmt.Sprintf("Successfully downloaded the certificates from S3 for %s", domainRoot))

	return certS3Writer.Bytes(), privateKeyS3Writer.Bytes(), nil
}

func (s *S3ACMEStorage) LoadUser(emailAddress string) (DomainUser, error) {

	filename := fmt.Sprintf("%s.json", emailAddress)
	filename = path.Join(s.serviceName, filename)
	userData := make([]byte, 0)
	userS3Writer := manager.NewWriteAtBuffer(userData)

	_, err := s.downloader.Download(context.TODO(), userS3Writer, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(filename),
	})
	if err != nil {
		return DomainUser{}, fmt.Errorf("error reading user file from S3: %s", err)
	}

	var user DomainUser
	err = json.Unmarshal(userS3Writer.Bytes(), &user)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error unmarshalling user: %s", err)
	}

	// load the private key
	keyFilename := fmt.Sprintf("%s.pem", emailAddress)
	keyFilename = path.Join(s.serviceName, keyFilename)
	keyData := make([]byte, 0)
	keyS3Writer := manager.NewWriteAtBuffer(keyData)

	_, err = s.downloader.Download(context.TODO(), keyS3Writer, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(keyFilename),
	})
	if err != nil {
		return DomainUser{}, fmt.Errorf("error reading private key file from S3: %s", err)
	}

	block, _ := pem.Decode(keyS3Writer.Bytes())
	if block == nil || block.Type != "PRIVATE KEY" {
		return DomainUser{}, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return DomainUser{}, fmt.Errorf("error parsing private key: %s", err)
	}

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

func (s *S3ACMEStorage) SaveUser(user DomainUser) error {

	userJson, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("error marshalling user: %s", err)
	}

	filename := fmt.Sprintf("%s.json", user.Email)
	filename = path.Join(s.serviceName, filename)
	_, err = s.s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(filename),
		Body:   bytes.NewReader(userJson),
	})
	if err != nil {
		return fmt.Errorf("error writing user to S3: %s", err)
	}
	// Marshal the private key into a PKCS8 format
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(user.key)
	if err != nil {
		return fmt.Errorf("error marshalling private key: %s", err)
	}

	// Create a pem.Block with the private key
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	// Encode the private key into PEM format
	privateKeyPem := pem.EncodeToMemory(privateKeyBlock)

	keyFilename := fmt.Sprintf("%s.pem", user.Email)
	keyFilename = path.Join(s.serviceName, keyFilename)
	_, err = s.s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(keyFilename),
		Body:   strings.NewReader(string(privateKeyPem)),
	})
	if err != nil {
		return fmt.Errorf("error writing private key to S3: %s", err)
	}
	return nil
}

func (s *S3ACMEStorage) SaveRegistration(reg *registration.Resource) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	_, err = s.s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(path.Join(s.serviceName, "certs", "registration.json")),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("error writing registration to S3: %s", err)
	}

	return nil
}

func (s *S3ACMEStorage) LoadRegistration() (*registration.Resource, error) {

	data := make([]byte, 0)
	dataWriter := manager.NewWriteAtBuffer(data)

	_, err := s.downloader.Download(context.TODO(), dataWriter, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(path.Join(s.serviceName, "certs", "registration.json")),
	})
	if err != nil {
		return nil, fmt.Errorf("error reading registration file from S3: %s", err)
	}

	var reg registration.Resource
	err = json.Unmarshal(dataWriter.Bytes(), &reg)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling registration: %s", err)
	}

	return &reg, nil
}

// UpdateTLS checks the TLS certificates for the given domains and renews them if they are expired or about to expire.
func (s *S3ACMEStorage) UpdateTLS(domainGroup []string) error {

	slog.Debug("Starting certificate check for ", "domains", domainGroup)

	domainRoot := domainGroup[0]

	certData, privateKeyData, err := s.DownloadCert(domainRoot)
	if err != nil {
		slog.Error("error while downloading certificates from S3", "error", err)
	}

	slog.Debug("Checking certificate expiry", "domains", domainGroup)
	timeToRenewCert, err := certExpiresSoon(certData, MaxRemainingDaysBeforeCertExpiry)
	if err != nil {
		slog.Error("error checking certificate expiry. Getting new ACME cert...", "error", err)
		timeToRenewCert = true
	}
	if timeToRenewCert {
		fmt.Println("Renewing certificate via ACME protocol...")
		certData, privateKeyData, err = renewACMECertificate(renewACMECertificateParams{
			email:          s.contactEmail,
			domains:        domainGroup,
			caAuthorityURL: s.caAuthority,
			s:              s,
		})
		if err != nil {
			// TODO: Do something about this
			return fmt.Errorf("error renewing ACME certificate: %v", err)
		}
		fmt.Println("Certificate renewed successfully via ACME protocol.")
		err = s.SaveCert(domainRoot, certData, privateKeyData)
		if err != nil {
			// TODO: Send SMS alerts if something like this is going on
			return fmt.Errorf("error uploading cert to s3: %v", err)
		}
	}
	if certData == nil || privateKeyData == nil || len(certData) == 0 || len(privateKeyData) == 0 {
		slog.Error("certData or privateKeyData is nil or empty after renewal process!!!")
		slog.Warn("Creating a self-signed cert to use in lieu of expected ACME cert stored in S3...", "certData", certData, "privateKeyData", privateKeyData)
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
