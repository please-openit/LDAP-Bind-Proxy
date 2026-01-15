# LDAP Bind Proxy - Quick Reference

## Installation

```bash
pip install -r requirements.txt
```

## Basic Usage (No TLS)

```bash
export LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
export LDAP_PROXY_CLIENT_ID=ldap-proxy
export LDAP_PROXY_CLIENT_SECRET=your-secret
python ldap_bind_proxy.py
```

## TLS Modes

### LDAPS Only (Recommended for Production)

```bash
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
python ldap_bind_proxy.py
# Listens on port 636 (LDAPS)
```

### LDAPS + STARTTLS

```bash
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
export LDAP_PROXY_ENABLE_PLAIN=true
export LDAP_PROXY_ENABLE_STARTTLS=true
python ldap_bind_proxy.py
# Listens on port 636 (LDAPS) and 389 (LDAP with STARTTLS)
```

### Mutual TLS (mTLS)

```bash
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
export LDAP_PROXY_TLS_CAFILE=./ca.crt
export LDAP_PROXY_REQUIRE_CLIENT_CERT=true
python ldap_bind_proxy.py
# Requires client certificates
```

## Generate Test Certificates

```bash
# Self-signed server certificate
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=localhost"

# Or use the test script
python tests/test_integration.py --generate-certs ./certs
```

## Testing

```bash
# Run all tests
./run_tests.sh

# Unit tests only
python -m pytest tests/test_tls_support.py -v

# Integration tests
python tests/test_integration.py --all

# Test LDAPS connection
ldapsearch -H ldaps://localhost:636 \
  -D "cn=test,dc=example,dc=org" -w test -x

# Test STARTTLS
ldapsearch -H ldap://localhost:389 \
  -D "cn=test,dc=example,dc=org" -w test -x -ZZ
```

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| LDAP_PROXY_TLS_CERTFILE | Server cert path | None |
| LDAP_PROXY_TLS_KEYFILE | Server key path | None |
| LDAP_PROXY_TLS_CAFILE | CA cert path | None |
| LDAP_PROXY_TLS_PORT | LDAPS port | 636 |
| LDAP_PROXY_PORT | LDAP port | 389 |
| LDAP_PROXY_ENABLE_PLAIN | Enable plain LDAP | false |
| LDAP_PROXY_REQUIRE_CLIENT_CERT | Require client cert | false |
| LDAP_PROXY_ENABLE_STARTTLS | Enable STARTTLS | false |
| LDAP_PROXY_TOKEN_URL | OIDC token URL | Required |
| LDAP_PROXY_CLIENT_ID | OIDC client ID | Required |
| LDAP_PROXY_CLIENT_SECRET | OIDC client secret | Required |

## Docker

```bash
# Build
docker build -t ldap-bind-proxy .

# Run with TLS
docker run -d \
  -p 636:636 -p 389:389 \
  -v ./certs:/app/certs:ro \
  -e LDAP_PROXY_TLS_CERTFILE=/app/certs/server.crt \
  -e LDAP_PROXY_TLS_KEYFILE=/app/certs/server.key \
  -e LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/... \
  -e LDAP_PROXY_CLIENT_ID=ldap-proxy \
  -e LDAP_PROXY_CLIENT_SECRET=secret \
  ldap-bind-proxy

# Or use docker-compose
docker-compose up -d
```

## Common Commands

```bash
# Check if proxy is running
nc -zv localhost 636  # LDAPS
nc -zv localhost 389  # LDAP

# Test bind with ldapwhoami
ldapwhoami -H ldaps://localhost:636 \
  -D "cn=user,dc=example,dc=org" -w password -x

# View logs (systemd)
journalctl -u ldap-bind-proxy -f

# Restart service
sudo systemctl restart ldap-bind-proxy
```

## Troubleshooting

```bash
# Verify certificate
openssl x509 -in server.crt -text -noout

# Test certificate and key match
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# Hashes should match

# Check port availability
lsof -i :636
lsof -i :389

# Test TLS connection
openssl s_client -connect localhost:636 -showcerts
```

## Documentation

- **README.md** - Overview and quick start
- **TLS-GUIDE.md** - Complete TLS configuration guide
- **SETUP.md** - Deployment and operations guide
- **IMPLEMENTATION_SUMMARY.md** - Technical details

## Support

- GitHub: https://github.com/please-openit/LDAP-Bind-Proxy
- Issues: https://github.com/please-openit/LDAP-Bind-Proxy/issues
