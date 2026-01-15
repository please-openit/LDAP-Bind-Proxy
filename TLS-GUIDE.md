# TLS/SSL Configuration Guide

## Overview

LDAP-Bind-Proxy now supports comprehensive TLS/SSL encryption with the following features:

- **LDAPS** - Implicit TLS on port 636 (recommended for production)
- **STARTTLS** - Explicit TLS upgrade on port 389 (for compatibility)
- **mTLS** - Mutual TLS with client certificate verification
- **CA Validation** - Custom CA certificate support

## Quick Start

### 1. Generate Self-Signed Certificates (Testing Only)

For production, use certificates from a trusted CA.

```bash
# Generate server certificate and key
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=localhost"
```

### 2. Configure Environment Variables

```bash
# Required for TLS
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key

# Optional TLS settings
export LDAP_PROXY_TLS_PORT=636              # LDAPS port (default: 636)
export LDAP_PROXY_PORT=389                  # Plain LDAP port (default: 389)
export LDAP_PROXY_ENABLE_PLAIN=false        # Enable plain LDAP when TLS is configured

# mTLS configuration (optional)
export LDAP_PROXY_TLS_CAFILE=./ca.crt       # CA certificate for client verification
export LDAP_PROXY_REQUIRE_CLIENT_CERT=false # Require client certificates

# OIDC configuration (required)
export LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
export LDAP_PROXY_CLIENT_ID=ldap-proxy
export LDAP_PROXY_CLIENT_SECRET=your-secret
```

### 3. Start the Proxy

```bash
python ldap_bind_proxy.py
```

## Configuration Scenarios

### Scenario 1: LDAPS Only (Most Secure)

```bash
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
# Plain LDAP disabled by default
python ldap_bind_proxy.py
```

**Result:** LDAPS listener on port 636 only.

### Scenario 2: LDAPS + Plain LDAP with STARTTLS

```bash
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
export LDAP_PROXY_ENABLE_PLAIN=true
python ldap_bind_proxy.py
```

**Result:**
- LDAPS on port 636 (implicit TLS)
- Plain LDAP on port 389 with STARTTLS support

### Scenario 3: mTLS (Mutual Authentication)

```bash
# Generate CA and client certificates first
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
export LDAP_PROXY_TLS_CAFILE=./ca.crt
export LDAP_PROXY_REQUIRE_CLIENT_CERT=true
python ldap_bind_proxy.py
```

**Result:** LDAPS on port 636 with client certificate verification.

### Scenario 4: Plain LDAP Only (Development/Testing)

```bash
# No TLS environment variables set
python ldap_bind_proxy.py
```

**Result:** Plain LDAP on port 389 (no encryption).

## Generating Certificates for mTLS

### Create a Certificate Authority (CA)

```bash
# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key \
  -sha256 -days 1024 -out ca.crt \
  -subj "/CN=Test CA"
```

### Create Server Certificate

```bash
# Generate server private key
openssl genrsa -out server.key 2048

# Create certificate signing request
openssl req -new -key server.key -out server.csr \
  -subj "/CN=localhost"

# Sign with CA
openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256
```

### Create Client Certificate

```bash
# Generate client private key
openssl genrsa -out client.key 2048

# Create certificate signing request
openssl req -new -key client.key -out client.csr \
  -subj "/CN=ldap-client"

# Sign with CA
openssl x509 -req -in client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256
```

## Testing TLS Connections

### Using ldapsearch (LDAPS)

```bash
# Test LDAPS connection (port 636)
ldapsearch -H ldaps://localhost:636 \
  -D "cn=test,dc=example,dc=org" \
  -w testpassword \
  -b "dc=example,dc=org" \
  -x

# With custom CA (for self-signed certs)
LDAPTLS_CACERT=./ca.crt ldapsearch -H ldaps://localhost:636 \
  -D "cn=test,dc=example,dc=org" \
  -w testpassword \
  -b "dc=example,dc=org" \
  -x
```

### Using ldapsearch (STARTTLS)

```bash
# Test STARTTLS on plain LDAP port (389)
ldapsearch -H ldap://localhost:389 \
  -D "cn=test,dc=example,dc=org" \
  -w testpassword \
  -b "dc=example,dc=org" \
  -x -Z

# -Z: Use STARTTLS
# -ZZ: Require STARTTLS (fail if not available)
```

### Using Python ldap3 Library

```python
from ldap3 import Server, Connection, Tls
import ssl

# LDAPS connection
tls = Tls(validate=ssl.CERT_NONE)  # For self-signed certs
server = Server('localhost', port=636, use_ssl=True, tls=tls)
conn = Connection(server, user='cn=test,dc=example,dc=org', password='testpassword')
conn.bind()
print(conn.result)

# STARTTLS connection
server = Server('localhost', port=389)
conn = Connection(server, user='cn=test,dc=example,dc=org', password='testpassword')
conn.start_tls()
conn.bind()
print(conn.result)
```

### Using the Integration Test Script

```bash
# Generate test certificates
python tests/test_integration.py --generate-certs ./certs

# Run all tests
python tests/test_integration.py --all

# Test specific feature
python tests/test_integration.py --test-ldaps
python tests/test_integration.py --test-starttls
```

## Running Unit Tests

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run unit tests
python -m pytest tests/test_tls_support.py -v

# Run with coverage
python -m pytest tests/test_tls_support.py --cov=ldap_bind_proxy --cov-report=html
```

## Environment Variables Reference

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LDAP_PROXY_TLS_CERTFILE` | Path to server certificate file | None | For TLS |
| `LDAP_PROXY_TLS_KEYFILE` | Path to server private key file | None | For TLS |
| `LDAP_PROXY_TLS_CAFILE` | Path to CA certificate for client verification | None | For mTLS |
| `LDAP_PROXY_TLS_PORT` | LDAPS port number | 636 | No |
| `LDAP_PROXY_PORT` | Plain LDAP port number | 389 | No |
| `LDAP_PROXY_ENABLE_PLAIN` | Enable plain LDAP when TLS configured | false | No |
| `LDAP_PROXY_REQUIRE_CLIENT_CERT` | Require client certificates (mTLS) | false | No |
| `LDAP_PROXY_TOKEN_URL` | OIDC token endpoint URL | None | Yes |
| `LDAP_PROXY_CLIENT_ID` | OIDC client ID | None | Yes |
| `LDAP_PROXY_CLIENT_SECRET` | OIDC client secret | None | Yes |

## Security Best Practices

### Production Deployment

1. **Use Certificates from Trusted CA**
   - Never use self-signed certificates in production
   - Use Let's Encrypt or your organization's PKI

2. **Enable TLS Only**
   - Set `LDAP_PROXY_ENABLE_PLAIN=false` (default)
   - Only expose LDAPS port 636

3. **Consider mTLS for Enhanced Security**
   - Set `LDAP_PROXY_REQUIRE_CLIENT_CERT=true`
   - Distribute client certificates securely

4. **Use Strong Ciphers**
   - The proxy uses OpenSSL defaults which prefer strong ciphers
   - Disable SSLv2 and SSLv3 (done automatically)

5. **Secure Certificate Storage**
   - Protect private keys with appropriate file permissions
   ```bash
   chmod 600 server.key
   chmod 644 server.crt
   ```

6. **Regular Certificate Rotation**
   - Renew certificates before expiration
   - Automate renewal with cert-manager or similar tools

### Network Security

1. **Firewall Configuration**
   - Only expose necessary ports (636 for LDAPS, 389 for LDAP/STARTTLS)
   - Restrict access to trusted networks

2. **Use Reverse Proxy**
   - Consider placing behind HAProxy or nginx for additional security layers
   - Enable rate limiting and connection limits

3. **Monitor and Log**
   - Enable comprehensive logging
   - Monitor for failed TLS handshakes
   - Alert on certificate expiration

## Troubleshooting

### Certificate Errors

**Problem:** `Certificate verify failed`

**Solution:**
- Ensure server certificate CN/SAN matches hostname
- For self-signed certs, configure client to trust CA
- Check certificate expiration dates

### STARTTLS Not Available

**Problem:** `STARTTLS not available`

**Solution:**
```bash
# Ensure TLS cert and key are configured
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key

# Enable plain LDAP and STARTTLS
export LDAP_PROXY_ENABLE_PLAIN=true
```

### mTLS Client Rejection

**Problem:** Client certificate rejected

**Solution:**
- Verify client certificate is signed by configured CA
- Check certificate is not expired
- Ensure CA file path is correct

### Port Already in Use

**Problem:** `Address already in use`

**Solution:**
```bash
# Check what's using the port
lsof -i :636  # or :389

# Change port if needed
export LDAP_PROXY_TLS_PORT=1636
export LDAP_PROXY_PORT=1389
```

## Docker Support

### Build with TLS Support

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ldap_bind_proxy.py .
COPY certs/ /app/certs/

ENV LDAP_PROXY_TLS_CERTFILE=/app/certs/server.crt
ENV LDAP_PROXY_TLS_KEYFILE=/app/certs/server.key

EXPOSE 636 389

CMD ["python", "ldap_bind_proxy.py"]
```

### Docker Compose with TLS

```yaml
services:
  ldap-proxy:
    build: .
    ports:
      - "636:636"
      - "389:389"
    environment:
      - LDAP_PROXY_TLS_CERTFILE=/app/certs/server.crt
      - LDAP_PROXY_TLS_KEYFILE=/app/certs/server.key
      - LDAP_PROXY_ENABLE_PLAIN=true
      - LDAP_PROXY_TOKEN_URL=https://keycloak:8080/realms/myrealm/protocol/openid-connect/token
      - LDAP_PROXY_CLIENT_ID=ldap-proxy
      - LDAP_PROXY_CLIENT_SECRET=secret
    volumes:
      - ./certs:/app/certs:ro
```

## Performance Considerations

- TLS adds ~5-10% CPU overhead
- Connection pooling recommended for clients
- Consider hardware TLS acceleration for high-throughput scenarios
- Monitor connection counts and adjust OS limits if needed

## Compliance

This implementation supports:
- TLS 1.2 and TLS 1.3
- Modern cipher suites
- Perfect Forward Secrecy (PFS)
- Certificate-based authentication (mTLS)

Suitable for:
- HIPAA compliance (with proper configuration)
- PCI-DSS requirements
- GDPR data protection requirements
- SOC 2 security controls
