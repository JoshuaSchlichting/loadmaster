# loadmaster

A lightweight certificate manager that automates ACME HTTP-01 challenges and renewals for groups of domains. It loads configuration from JSON files, provisions or refreshes certificates, and watches for changes to your domains list to update certificates on the fly. Optional S3-backed storage lets you centralize certificate material; otherwise certificates are stored locally.

## How it works

- At startup:
  - Reads `config.json` and `domains.json` (defaults under `~/.loadmaster`).
  - Ensures the local certificate directory exists.
  - Selects storage:
    - S3-backed if `s3.bucketName` is set in `config.json`.
    - Local storage otherwise.
  - For each domain group in `domains.json`, calls `UpdateTLS` to retrieve from cache and refresh if expiring; falls back to self-signed only if cache is missing.
    - > A "domain group" is a collection of domains that share the same certificate. (e.g., `example.com`, `www.example.com`, `mail.example.com`)
- Long-running process:
  - Watches `domains.json` for changes and re-runs `UpdateTLS` for each group on write/create.
  - Also triggers a refresh loop every 24 hours, upgrading certs that are close to expiring.

ACME HTTP-01 challenges are served on a configurable port (default: `5002`). You should proxy `/.well-known/acme-challenge/*` requests to this port from your public HTTP endpoint.

## Configuration

By default, the app looks in `~/.loadmaster` for `config.json` and `domains.json`. If either file is missing, it will create a default version, print a message to edit the file, and exit.

- Default directory: `~/.loadmaster` (`config.DefaultConfigDir`)
- Default paths:
  - `~/.loadmaster/config.json`
  - `~/.loadmaster/domains.json`
- Local certificate directory:
  - Defaults to `~/.loadmaster/certs` unless overridden internally.
  - Created automatically if it does not exist.

### `config.json`

Fields:
- `email` (string): Contact email used for ACME registration.
- `caAuthority` (string): ACME CA directory URL. Defaults to Let’s Encrypt staging: `https://acme-staging-v02.api.letsencrypt.org/directory`.
- `s3` (object): Optional S3 settings for remote storage.
  - `bucketName` (string): If set, S3 storage is used.
  - `endpoint` (string): Custom S3-compatible endpoint (optional).
  - `region` (string): AWS region for the bucket.

Example:
```/dev/null/config.json#L1-16
{
  "email": "admin@example.com",
  "caAuthority": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "s3": {
    "bucketName": "my-certificates",
    "endpoint": "",
    "region": "us-east-1"
  }
}
```

Notes:
- Use the production Let’s Encrypt directory when you’re ready: `https://acme-v02.api.letsencrypt.org/directory`.
- When `s3.bucketName` is non-empty, the app constructs S3 storage with:
  - `BucketName`, `ContactEmail`, `LocalCertDir`, `CAAuthority`
- Otherwise, local storage is used via `acme.NewLocalACMEStorage(email, caAuthority)`.

### `domains.json`

Fields:
- `domains` (array of arrays of strings): Each inner array is a domain group that will share a certificate (e.g., primary domain plus its aliases).

Example:
```/dev/null/domains.json#L1-10
{
  "domains": [
    ["example.com", "www.example.com"],
    ["api.example.com", "api.internal.example.com"]
  ]
}
```

Notes:
- On startup and on any change to `domains.json`, each group is processed via `storage.UpdateTLS(group)`.

## Running

You can run the binary with optional flags to point at config files and set the ACME challenge port.

Flags:
- `-domains` (string): Path to `domains.json`. Default: `~/.loadmaster/domains.json`.
- `-config` (string): Path to `config.json`. Default: `~/.loadmaster/config.json`.
- `-port` (int): Port to serve ACME HTTP-01 challenges. Default: `5002`.

Example:
```/dev/null/run.sh#L1-3
./loadmaster \
  -config "$HOME/.loadmaster/config.json" \
  -domains "$HOME/.loadmaster/domains.json" \
  -port 5002
```

Behavior:
- Logs startup info and file paths.
- Ensures `LocalCertDir` exists (default `~/.loadmaster/certs`).
- Loads domains and processes each group.
- Watches `domains.json` for writes/creates with a short delay to ensure complete writes.
- Every 24 hours, triggers a refresh pass for all domain groups.

## Example NGINX proxy for ACME challenges

```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    
    # Proxy ACME HTTP-01 challenge requests to the cert manager
    location ^~ /.well-known/acme-challenge/ {
    proxy_pass http://127.0.0.1:5002;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_read_timeout 30s;
}
```

## License
GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
