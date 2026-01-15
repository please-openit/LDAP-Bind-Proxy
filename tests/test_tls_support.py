#!/usr/bin/env python
"""
Comprehensive test suite for LDAP Bind Proxy TLS support.

Tests cover:
- LDAPS (implicit TLS)
- STARTTLS (explicit TLS upgrade)
- mTLS (mutual TLS with client certificates)
- CA validation
- Configuration validation
"""

import unittest
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from OpenSSL import crypto
from twisted.internet import reactor, defer
from twisted.test import proto_helpers
from twisted.internet.ssl import CertificateOptions

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldap_bind_proxy import Configuration, OidcProxy, create_ssl_context_factory
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors


class CertificateGenerator:
    """Helper class to generate test certificates."""
    
    @staticmethod
    def generate_self_signed_cert(common_name="localhost"):
        """Generate a self-signed certificate for testing."""
        # Create key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create certificate
        cert = crypto.X509()
        cert.get_subject().CN = common_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        
        return cert_pem, key_pem
    
    @staticmethod
    def generate_ca_and_client_cert():
        """Generate CA certificate and a client certificate signed by the CA."""
        # Generate CA
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 2048)
        
        ca_cert = crypto.X509()
        ca_cert.get_subject().CN = "Test CA"
        ca_cert.set_serial_number(1)
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        ])
        ca_cert.sign(ca_key, 'sha256')
        
        # Generate client certificate
        client_key = crypto.PKey()
        client_key.generate_key(crypto.TYPE_RSA, 2048)
        
        client_cert = crypto.X509()
        client_cert.get_subject().CN = "test-client"
        client_cert.set_serial_number(2)
        client_cert.gmtime_adj_notBefore(0)
        client_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        client_cert.set_issuer(ca_cert.get_subject())
        client_cert.set_pubkey(client_key)
        client_cert.sign(ca_key, 'sha256')
        
        ca_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
        client_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert)
        client_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key)
        
        return ca_cert_pem, client_cert_pem, client_key_pem


class TestConfiguration(unittest.TestCase):
    """Test Configuration class."""
    
    def setUp(self):
        """Clear environment variables before each test."""
        self.env_backup = os.environ.copy()
        for key in list(os.environ.keys()):
            if key.startswith('LDAP_PROXY_'):
                del os.environ[key]
    
    def tearDown(self):
        """Restore environment variables after each test."""
        os.environ.clear()
        os.environ.update(self.env_backup)
    
    def test_default_configuration(self):
        """Test default configuration values."""
        config = Configuration()
        self.assertIsNone(config.tls_certfile)
        self.assertIsNone(config.tls_keyfile)
        self.assertIsNone(config.tls_cafile)
        self.assertEqual(config.tls_port, 636)
        self.assertEqual(config.plain_port, 389)
        self.assertFalse(config.enable_plain)
        self.assertFalse(config.require_client_cert)
        self.assertFalse(config.enable_starttls)
    
    def test_tls_configuration(self):
        """Test TLS configuration from environment variables."""
        os.environ['LDAP_PROXY_TLS_CERTFILE'] = '/path/to/cert.pem'
        os.environ['LDAP_PROXY_TLS_KEYFILE'] = '/path/to/key.pem'
        os.environ['LDAP_PROXY_TLS_CAFILE'] = '/path/to/ca.pem'
        os.environ['LDAP_PROXY_TLS_PORT'] = '1636'
        os.environ['LDAP_PROXY_PORT'] = '1389'
        os.environ['LDAP_PROXY_ENABLE_PLAIN'] = 'true'
        os.environ['LDAP_PROXY_REQUIRE_CLIENT_CERT'] = 'yes'
        os.environ['LDAP_PROXY_ENABLE_STARTTLS'] = '1'
        
        config = Configuration()
        self.assertEqual(config.tls_certfile, '/path/to/cert.pem')
        self.assertEqual(config.tls_keyfile, '/path/to/key.pem')
        self.assertEqual(config.tls_cafile, '/path/to/ca.pem')
        self.assertEqual(config.tls_port, 1636)
        self.assertEqual(config.plain_port, 1389)
        self.assertTrue(config.enable_plain)
        self.assertTrue(config.require_client_cert)
        self.assertTrue(config.enable_starttls)


class TestSSLContextFactory(unittest.TestCase):
    """Test SSL context factory creation."""
    
    def setUp(self):
        """Create temporary directory for test certificates."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = Configuration()
    
    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.temp_dir)
    
    def test_create_ssl_context_without_certs(self):
        """Test that SSL context returns None without certificates."""
        context = create_ssl_context_factory(self.config)
        self.assertIsNone(context)
    
    def test_create_ssl_context_with_server_cert(self):
        """Test SSL context creation with server certificate."""
        cert_pem, key_pem = CertificateGenerator.generate_self_signed_cert()
        
        cert_path = os.path.join(self.temp_dir, 'server.crt')
        key_path = os.path.join(self.temp_dir, 'server.key')
        
        with open(cert_path, 'wb') as f:
            f.write(cert_pem)
        with open(key_path, 'wb') as f:
            f.write(key_pem)
        
        self.config.tls_certfile = cert_path
        self.config.tls_keyfile = key_path
        
        context = create_ssl_context_factory(self.config)
        self.assertIsNotNone(context)
        self.assertIsInstance(context, CertificateOptions)
    
    def test_create_ssl_context_with_mtls(self):
        """Test SSL context creation with mTLS (client cert verification)."""
        ca_pem, client_cert_pem, client_key_pem = CertificateGenerator.generate_ca_and_client_cert()
        server_cert_pem, server_key_pem = CertificateGenerator.generate_self_signed_cert()
        
        ca_path = os.path.join(self.temp_dir, 'ca.crt')
        cert_path = os.path.join(self.temp_dir, 'server.crt')
        key_path = os.path.join(self.temp_dir, 'server.key')
        
        with open(ca_path, 'wb') as f:
            f.write(ca_pem)
        with open(cert_path, 'wb') as f:
            f.write(server_cert_pem)
        with open(key_path, 'wb') as f:
            f.write(server_key_pem)
        
        self.config.tls_certfile = cert_path
        self.config.tls_keyfile = key_path
        self.config.tls_cafile = ca_path
        self.config.require_client_cert = True
        
        context = create_ssl_context_factory(self.config)
        self.assertIsNotNone(context)
        self.assertIsInstance(context, CertificateOptions)


class TestOidcProxySTARTTLS(unittest.TestCase):
    """Test STARTTLS functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = Configuration()
        self.config.url = "http://test.example.com/token"
        self.config.client_id = "test-client"
        self.config.client_secret = "test-secret"
        
        # Create temporary certs
        self.temp_dir = tempfile.mkdtemp()
        cert_pem, key_pem = CertificateGenerator.generate_self_signed_cert()
        
        cert_path = os.path.join(self.temp_dir, 'server.crt')
        key_path = os.path.join(self.temp_dir, 'server.key')
        
        with open(cert_path, 'wb') as f:
            f.write(cert_pem)
        with open(key_path, 'wb') as f:
            f.write(key_pem)
        
        self.config.tls_certfile = cert_path
        self.config.tls_keyfile = key_path
        
        self.ssl_context = create_ssl_context_factory(self.config)
        self.proxy = OidcProxy(self.config, self.ssl_context)
        
        # Mock client
        self.proxy.client = Mock()
        
        # Create fake transport
        self.transport = proto_helpers.StringTransport()
        self.transport.startTLS = Mock()
        self.proxy.transport = self.transport
    
    def tearDown(self):
        """Clean up."""
        shutil.rmtree(self.temp_dir)
    
    def test_starttls_request_with_tls_configured(self):
        """Test STARTTLS request when TLS is configured."""
        request = pureldap.LDAPExtendedRequest(
            requestName='1.3.6.1.4.1.1466.20037'
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPExtendedResponse)
        self.assertEqual(response.resultCode, ldaperrors.Success.resultCode)
        self.transport.startTLS.assert_called_once_with(self.ssl_context)
        self.assertTrue(self.proxy.tls_started)
    
    def test_starttls_request_without_tls_configured(self):
        """Test STARTTLS request when TLS is not configured."""
        proxy_no_tls = OidcProxy(self.config, None)
        proxy_no_tls.client = Mock()
        proxy_no_tls.transport = self.transport
        
        request = pureldap.LDAPExtendedRequest(
            requestName='1.3.6.1.4.1.1466.20037'
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        proxy_no_tls.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPExtendedResponse)
        self.assertEqual(response.resultCode, ldaperrors.LDAPUnavailable.resultCode)
        self.transport.startTLS.assert_not_called()
    
    def test_starttls_already_established(self):
        """Test STARTTLS request when TLS is already active."""
        self.proxy.tls_started = True
        
        request = pureldap.LDAPExtendedRequest(
            requestName='1.3.6.1.4.1.1466.20037'
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPExtendedResponse)
        self.assertEqual(response.resultCode, ldaperrors.LDAPOperationsError.resultCode)
        self.transport.startTLS.assert_not_called()


class TestOidcProxyBindRequest(unittest.TestCase):
    """Test LDAP bind request handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = Configuration()
        self.config.url = "http://test.example.com/token"
        self.config.client_id = "test-client"
        self.config.client_secret = "test-secret"
        
        self.proxy = OidcProxy(self.config, None)
        self.proxy.client = Mock()
    
    @patch('ldap_bind_proxy.requests.request')
    def test_successful_bind(self, mock_request):
        """Test successful LDAP bind with valid OIDC credentials."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        request = pureldap.LDAPBindRequest(
            dn=b'cn=testuser,ou=people,dc=example,dc=org',
            auth=b'testpassword'
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPBindResponse)
        self.assertEqual(response.resultCode, ldaperrors.Success.resultCode)
        
        # Verify OIDC request was made
        mock_request.assert_called_once()
    
    @patch('ldap_bind_proxy.requests.request')
    def test_failed_bind(self, mock_request):
        """Test failed LDAP bind with invalid OIDC credentials."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response
        
        request = pureldap.LDAPBindRequest(
            dn=b'cn=testuser,ou=people,dc=example,dc=org',
            auth=b'wrongpassword'
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPBindResponse)
        self.assertEqual(response.resultCode, ldaperrors.LDAPInvalidCredentials.resultCode)


class TestOidcProxyOtherRequests(unittest.TestCase):
    """Test handling of other LDAP operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = Configuration()
        self.proxy = OidcProxy(self.config, None)
        self.proxy.client = Mock()
    
    def test_search_request(self):
        """Test LDAP search request handling."""
        request = pureldap.LDAPSearchRequest(
            baseObject=b'dc=example,dc=org',
            scope=pureldap.LDAP_SCOPE_wholeSubtree,
            filter=pureldap.LDAPFilter_present('objectClass')
        )
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPSearchResultDone)
        self.assertEqual(response.resultCode, ldaperrors.Success.resultCode)
    
    def test_unbind_request(self):
        """Test LDAP unbind request handling."""
        request = pureldap.LDAPUnbindRequest()
        
        responses = []
        def reply(msg):
            responses.append(msg)
        
        self.proxy.handleBeforeForwardRequest(request, None, reply)
        
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertIsInstance(response, pureldap.LDAPBindResponse)
        self.assertEqual(response.resultCode, ldaperrors.Success.resultCode)


if __name__ == '__main__':
    unittest.main()
