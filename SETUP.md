# LDAP Bind Proxy - Setup and Deployment Guide

## Quick Start (Development)

### 1. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# OIDC Configuration (required)
export LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
export LDAP_PROXY_CLIENT_ID=ldap-proxy
export LDAP_PROXY_CLIENT_SECRET=your-secret

# Basic setup (plain LDAP, no encryption)
python ldap_bind_proxy.py
```

### 3. Test the Connection

```bash
# In another terminal
ldapsearch -H ldap://localhost:389 \
  -D "cn=test,dc=example,dc=org" \
  -w testpassword \
  -b "dc=example,dc=org" \
  -x
```

## Production Setup with TLS

### Step 1: Obtain TLS Certificates

#### Option A: Using Let's Encrypt (Recommended for Production)

```bash
# Install certbot
sudo apt-get install certbot  # Ubuntu/Debian
# or
brew install certbot  # macOS

# Obtain certificate
sudo certbot certonly --standalone -d ldap.example.com

# Certificates will be at:
# /etc/letsencrypt/live/ldap.example.com/fullchain.pem
# /etc/letsencrypt/live/ldap.example.com/privkey.pem
```

#### Option B: Using OpenSSL (Testing/Internal)

```bash
# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/ldap-proxy/server.key \
  -out /etc/ldap-proxy/server.crt \
  -days 365 \
  -subj "/CN=ldap.example.com" \
  -addext "subjectAltName=DNS:ldap.example.com,DNS:localhost,IP:127.0.0.1"

# Set permissions
chmod 600 /etc/ldap-proxy/server.key
chmod 644 /etc/ldap-proxy/server.crt
```

### Step 2: Configure TLS Environment

```bash
# TLS Configuration
export LDAP_PROXY_TLS_CERTFILE=/etc/ldap-proxy/server.crt
export LDAP_PROXY_TLS_KEYFILE=/etc/ldap-proxy/server.key
export LDAP_PROXY_TLS_PORT=636

# OIDC Configuration
export LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
export LDAP_PROXY_CLIENT_ID=ldap-proxy
export LDAP_PROXY_CLIENT_SECRET=your-secret

# Optional: Enable both LDAPS and plain LDAP with STARTTLS
export LDAP_PROXY_ENABLE_PLAIN=true
export LDAP_PROXY_ENABLE_STARTTLS=true
```

### Step 3: Start the Proxy

```bash
python ldap_bind_proxy.py
```

## Systemd Service (Linux)

Create `/etc/systemd/system/ldap-bind-proxy.service`:

```ini
[Unit]
Description=LDAP to OIDC Bind Proxy
After=network.target

[Service]
Type=simple
User=ldap-proxy
Group=ldap-proxy
WorkingDirectory=/opt/ldap-bind-proxy
Environment="LDAP_PROXY_TLS_CERTFILE=/etc/ldap-proxy/server.crt"
Environment="LDAP_PROXY_TLS_KEYFILE=/etc/ldap-proxy/server.key"
Environment="LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
Environment="LDAP_PROXY_CLIENT_ID=ldap-proxy"
EnvironmentFile=/etc/ldap-proxy/credentials
ExecStart=/opt/ldap-bind-proxy/venv/bin/python /opt/ldap-bind-proxy/ldap_bind_proxy.py
Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ldap-proxy

[Install]
WantedBy=multi-user.target
```

Create `/etc/ldap-proxy/credentials`:
```bash
LDAP_PROXY_CLIENT_SECRET=your-secret-here
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ldap-bind-proxy
sudo systemctl start ldap-bind-proxy
sudo systemctl status ldap-bind-proxy
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY ldap_bind_proxy.py .

# Create non-root user
RUN useradd -m -u 1000 ldap && \
    mkdir -p /app/certs && \
    chown -R ldap:ldap /app

USER ldap

# Expose ports
EXPOSE 389 636

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',389)); s.close()" || exit 1

CMD ["python", "ldap_bind_proxy.py"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  ldap-proxy:
    build: .
    container_name: ldap-bind-proxy
    restart: unless-stopped
    
    ports:
      - "389:389"
      - "636:636"
    
    volumes:
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
    
    environment:
      # TLS Configuration
      LDAP_PROXY_TLS_CERTFILE: /app/certs/server.crt
      LDAP_PROXY_TLS_KEYFILE: /app/certs/server.key
      LDAP_PROXY_ENABLE_PLAIN: "true"
      LDAP_PROXY_ENABLE_STARTTLS: "true"
      
      # OIDC Configuration
      LDAP_PROXY_TOKEN_URL: https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
      LDAP_PROXY_CLIENT_ID: ldap-proxy
      LDAP_PROXY_CLIENT_SECRET: ${LDAP_PROXY_CLIENT_SECRET}
    
    networks:
      - ldap-network
    
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  ldap-network:
    driver: bridge
```

Run with:
```bash
export LDAP_PROXY_CLIENT_SECRET=your-secret
docker-compose up -d
```

## Kubernetes Deployment

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ldap-proxy-credentials
type: Opaque
stringData:
  client-secret: your-secret-here
---
apiVersion: v1
kind: Secret
metadata:
  name: ldap-proxy-tls
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ldap-bind-proxy
  labels:
    app: ldap-bind-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ldap-bind-proxy
  template:
    metadata:
      labels:
        app: ldap-bind-proxy
    spec:
      containers:
      - name: ldap-proxy
        image: your-registry/ldap-bind-proxy:latest
        ports:
        - containerPort: 389
          name: ldap
        - containerPort: 636
          name: ldaps
        
        env:
        - name: LDAP_PROXY_TLS_CERTFILE
          value: /etc/tls/tls.crt
        - name: LDAP_PROXY_TLS_KEYFILE
          value: /etc/tls/tls.key
        - name: LDAP_PROXY_ENABLE_PLAIN
          value: "true"
        - name: LDAP_PROXY_ENABLE_STARTTLS
          value: "true"
        - name: LDAP_PROXY_TOKEN_URL
          value: https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
        - name: LDAP_PROXY_CLIENT_ID
          value: ldap-proxy
        - name: LDAP_PROXY_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: ldap-proxy-credentials
              key: client-secret
        
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/tls
          readOnly: true
        
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        
        livenessProbe:
          tcpSocket:
            port: 389
          initialDelaySeconds: 15
          periodSeconds: 20
        
        readinessProbe:
          tcpSocket:
            port: 389
          initialDelaySeconds: 5
          periodSeconds: 10
      
      volumes:
      - name: tls-certs
        secret:
          secretName: ldap-proxy-tls
---
apiVersion: v1
kind: Service
metadata:
  name: ldap-bind-proxy
spec:
  selector:
    app: ldap-bind-proxy
  ports:
  - name: ldap
    port: 389
    targetPort: 389
  - name: ldaps
    port: 636
    targetPort: 636
  type: LoadBalancer
```

## Monitoring and Logging

### Log to File

```bash
# Redirect logs to file
python ldap_bind_proxy.py 2>&1 | tee -a /var/log/ldap-proxy/proxy.log

# Or with systemd
# Add to service file:
StandardOutput=append:/var/log/ldap-proxy/proxy.log
StandardError=append:/var/log/ldap-proxy/error.log
```

### Prometheus Metrics (Future Enhancement)

The proxy can be enhanced with Prometheus metrics. Example additions:

- `ldap_bind_requests_total{status="success|failure"}`
- `ldap_bind_duration_seconds`
- `ldap_starttls_total`
- `ldap_active_connections`

## Troubleshooting

### Check if Proxy is Running

```bash
# Check LDAP port
nc -zv localhost 389

# Check LDAPS port
nc -zv localhost 636

# Test LDAP bind
ldapwhoami -H ldap://localhost:389 -D "cn=test,dc=example,dc=org" -w test -x
```

### Enable Debug Logging

```python
# Add to ldap_bind_proxy.py before log.startLogging():
import sys
log.startLogging(sys.stderr, setStdout=False)
```

### Common Issues

**Port Permission Denied (ports < 1024)**
```bash
# Option 1: Use higher ports
export LDAP_PROXY_TLS_PORT=1636
export LDAP_PROXY_PORT=1389

# Option 2: Allow Python to bind to low ports (Linux)
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3

# Option 3: Run as root (not recommended)
sudo python ldap_bind_proxy.py
```

**Certificate Issues**
```bash
# Verify certificate
openssl x509 -in server.crt -text -noout

# Check certificate matches key
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# Hashes should match
```

## Performance Tuning

### System Limits

```bash
# Increase file descriptors
ulimit -n 65536

# Add to /etc/security/limits.conf:
ldap-proxy soft nofile 65536
ldap-proxy hard nofile 65536
```

### Twisted Reactor Tuning

For high-throughput scenarios, consider using epoll reactor (Linux):

```python
# At the top of ldap_bind_proxy.py
from twisted.internet import epollreactor
epollreactor.install()
```

## Backup and Recovery

### Backup Configuration

```bash
#!/bin/bash
# backup-ldap-proxy.sh

BACKUP_DIR=/var/backups/ldap-proxy
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration
cp /etc/ldap-proxy/credentials $BACKUP_DIR/credentials.$DATE

# Backup certificates (if managed locally)
cp -r /etc/ldap-proxy/certs $BACKUP_DIR/certs.$DATE

# Keep last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete
```

## Security Checklist

- [ ] Use TLS certificates from trusted CA
- [ ] Store secrets in environment variables or secret management system
- [ ] Enable only LDAPS in production (disable plain LDAP)
- [ ] Set restrictive file permissions on private keys (600)
- [ ] Run proxy as non-root user
- [ ] Enable firewall rules to restrict access
- [ ] Implement rate limiting at network level
- [ ] Monitor failed authentication attempts
- [ ] Keep dependencies updated
- [ ] Enable audit logging
- [ ] Use mTLS for enhanced security
- [ ] Rotate certificates before expiration
