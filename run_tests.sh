#!/bin/bash
# Quick test runner for LDAP Bind Proxy

set -e

echo "LDAP Bind Proxy - Test Runner"
echo "=============================="
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version || { echo "Error: Python 3 not found"; exit 1; }
echo "✓ Python 3 installed"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "✓ Core dependencies installed"
echo ""

echo "Installing test dependencies..."
pip install -q -r requirements-test.txt
echo "✓ Test dependencies installed"
echo ""

# Run syntax check
echo "Running syntax check..."
python3 -m py_compile ldap_bind_proxy.py
echo "✓ Syntax check passed"
echo ""

# Run unit tests
echo "Running unit tests..."
if python3 -m pytest tests/test_tls_support.py -v --tb=short; then
    echo "✓ All unit tests passed"
else
    echo "✗ Some unit tests failed"
    exit 1
fi

echo ""
echo "=============================="
echo "All tests completed successfully!"
echo ""
echo "To run the proxy with TLS:"
echo "  1. Generate certificates: python tests/test_integration.py --generate-certs ./certs"
echo "  2. Configure environment: export LDAP_PROXY_TLS_CERTFILE=./certs/server.crt"
echo "  3. Start proxy: python ldap_bind_proxy.py"
echo ""
echo "See TLS-GUIDE.md for complete documentation"
