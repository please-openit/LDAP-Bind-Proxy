#! /usr/bin/env python
# Copyright 2024 please-open.it
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
LDAP client test script with TLS/SSL support.

Tests various TLS connection modes:
- LDAPS (implicit TLS on port 636)
- STARTTLS (explicit TLS upgrade on port 389)
- Plain LDAP (no encryption, port 389)

Usage:
    # Test LDAPS
    python ldap_client_bind_tls.py --ldaps
    
    # Test STARTTLS
    python ldap_client_bind_tls.py --starttls
    
    # Test plain LDAP
    python ldap_client_bind_tls.py --plain
"""

import sys
import argparse

from twisted.internet import defer, ssl
from twisted.internet.endpoints import clientFromString, connectProtocol, SSL4ClientEndpoint
from twisted.internet.task import react
from twisted.internet import reactor
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors

# Test credentials
BASEDN = b"dc=example,dc=org"
BINDDN = b"cn=test,ou=people,dc=example,dc=org"
BINDPW = b"pwtest"

# Server settings
LDAP_HOST = "localhost"
LDAP_PORT = 389
LDAPS_PORT = 636


class InsecureClientContextFactory:
    """SSL context factory that accepts self-signed certificates (for testing only)."""
    
    def getContext(self):
        import ssl as stdlib_ssl
        ctx = stdlib_ssl.SSLContext(stdlib_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = stdlib_ssl.CERT_NONE
        return ctx


@defer.inlineCallbacks
def test_ldaps_bind(host=LDAP_HOST, port=LDAPS_PORT):
    """Test LDAPS connection (implicit TLS on port 636)."""
    print(f"\n{'='*60}")
    print(f"Testing LDAPS (implicit TLS) on {host}:{port}")
    print(f"{'='*60}\n")
    
    try:
        # Create insecure SSL context factory that accepts self-signed certs
        from twisted.internet import ssl as twisted_ssl
        from OpenSSL import SSL
        
        class InsecureClientContextFactory:
            def getContext(self):
                ctx = SSL.Context(SSL.SSLv23_METHOD)
                ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
                return ctx
        
        # Create SSL endpoint
        from twisted.internet.endpoints import SSL4ClientEndpoint
        
        endpoint = SSL4ClientEndpoint(reactor, host, port, InsecureClientContextFactory())
        
        # Connect
        print("Connecting with TLS...")
        client = LDAPClient()
        proto = yield connectProtocol(endpoint, client)
        
        print("✓ TLS connection established")
        
        # Bind
        print(f"Binding as: {BINDDN.decode('utf-8')}")
        yield client.bind(BINDDN, BINDPW)
        print("✓ LDAP bind successful")
        
        # Query
        o = LDAPEntry(client, BASEDN)
        print(f"✓ Base DN: {o.dn}")
        
        yield client.unbind()
        print("✓ Connection closed\n")
        
        print("="*60)
        print("LDAPS test PASSED ✓")
        print("="*60)
        
    except Exception as ex:
        print(f"\n✗ LDAPS test FAILED:")
        print(f"  Error: {repr(ex)}\n")
        raise


@defer.inlineCallbacks
def test_starttls_bind(host=LDAP_HOST, port=LDAP_PORT):
    """Test STARTTLS connection (explicit TLS upgrade on port 389)."""
    print(f"\n{'='*60}")
    print(f"Testing STARTTLS (explicit TLS upgrade) on {host}:{port}")
    print(f"{'='*60}\n")
    
    try:
        # Connect to plain LDAP first
        endpoint_str = f"tcp:host={host}:port={port}"
        endpoint = clientFromString(reactor, endpoint_str)
        
        print("Connecting to plain LDAP...")
        client = LDAPClient()
        proto = yield connectProtocol(endpoint, client)
        print("✓ Plain LDAP connection established")
        
        # Send STARTTLS extended operation
        print("Sending STARTTLS request...")
        starttls_oid = '1.3.6.1.4.1.1466.20037'
        req = pureldap.LDAPExtendedRequest(requestName=starttls_oid)
        
        response = yield client.send(req)
        
        if response.resultCode == ldaperrors.Success.resultCode:
            print("✓ STARTTLS accepted by server")
            
            # Upgrade to TLS
            print("Upgrading connection to TLS...")
            from twisted.internet import ssl as twisted_ssl
            from OpenSSL import SSL
            
            # Create insecure SSL context that accepts any certificate (testing only!)
            class InsecureClientContextFactory:
                def getContext(self):
                    ctx = SSL.Context(SSL.SSLv23_METHOD)
                    ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
                    return ctx
            
            proto.transport.startTLS(InsecureClientContextFactory())
            print("✓ Connection upgraded to TLS")
            
            # Bind after TLS upgrade
            print(f"Binding as: {BINDDN.decode('utf-8')}")
            yield client.bind(BINDDN, BINDPW)
            print("✓ LDAP bind successful over TLS")
            
            # Query
            o = LDAPEntry(client, BASEDN)
            print(f"✓ Base DN: {o.dn.getText()}")
            
            yield client.unbind()
            print("✓ Connection closed\n")
            
            print("="*60)
            print("STARTTLS test PASSED ✓")
            print("="*60)
        else:
            print(f"✗ STARTTLS rejected by server: {response}")
            raise Exception("STARTTLS not available")
            
    except Exception as ex:
        print(f"\n✗ STARTTLS test FAILED:")
        print(f"  Error: {repr(ex)}\n")
        raise


@defer.inlineCallbacks
def test_plain_bind(host=LDAP_HOST, port=LDAP_PORT):
    """Test plain LDAP connection (no encryption)."""
    print(f"\n{'='*60}")
    print(f"Testing Plain LDAP (no encryption) on {host}:{port}")
    print(f"{'='*60}\n")
    
    try:
        # Connect
        endpoint_str = f"tcp:host={host}:port={port}"
        endpoint = clientFromString(reactor, endpoint_str)
        
        print("Connecting...")
        client = LDAPClient()
        proto = yield connectProtocol(endpoint, client)
        print("✓ Connection established")
        
        # Bind
        print(f"Binding as: {BINDDN.decode('utf-8')}")
        yield client.bind(BINDDN, BINDPW)
        print("✓ LDAP bind successful")
        
        # Query
        o = LDAPEntry(client, BASEDN)
        print(f"✓ Base DN: {o.dn.getText()}")
        
        yield client.unbind()
        print("✓ Connection closed\n")
        
        print("="*60)
        print("Plain LDAP test PASSED ✓")
        print("="*60)
        
    except Exception as ex:
        print(f"\n✗ Plain LDAP test FAILED:")
        print(f"  Error: {repr(ex)}\n")
        raise


def onError(err):
    """Error handler."""
    print("\n" + "="*60)
    print("TEST FAILED ✗")
    print("="*60)
    err.printDetailedTraceback(file=sys.stderr)


def main(reactor, *args):
    """Main test function."""
    parser = argparse.ArgumentParser(
        description='LDAP client test with TLS support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test LDAPS (implicit TLS on port 636)
  python ldap_client_bind_tls.py --ldaps
  
  # Test STARTTLS (explicit TLS upgrade on port 389)
  python ldap_client_bind_tls.py --starttls
  
  # Test plain LDAP (no encryption)
  python ldap_client_bind_tls.py --plain
  
  # Test all modes
  python ldap_client_bind_tls.py --all
  
  # Custom host and port
  python ldap_client_bind_tls.py --ldaps --host example.com --ldaps-port 1636

Note: This script accepts self-signed certificates for testing purposes.
      Do not use in production without proper certificate validation.
        """
    )
    
    parser.add_argument('--ldaps', action='store_true',
                       help='Test LDAPS (implicit TLS on port 636)')
    parser.add_argument('--starttls', action='store_true',
                       help='Test STARTTLS (explicit TLS upgrade on port 389)')
    parser.add_argument('--plain', action='store_true',
                       help='Test plain LDAP (no encryption on port 389)')
    parser.add_argument('--all', action='store_true',
                       help='Test all connection modes')
    
    parser.add_argument('--host', default=LDAP_HOST,
                       help=f'LDAP server hostname (default: {LDAP_HOST})')
    parser.add_argument('--port', type=int, default=LDAP_PORT,
                       help=f'LDAP server port for plain/STARTTLS (default: {LDAP_PORT})')
    parser.add_argument('--ldaps-port', type=int, default=LDAPS_PORT,
                       help=f'LDAPS server port (default: {LDAPS_PORT})')
    
    args = parser.parse_args(list(args))
    
    # If no mode specified, show help
    if not (args.ldaps or args.starttls or args.plain or args.all):
        parser.print_help()
        return defer.succeed(None)
    
    # Run tests
    d = defer.succeed(None)
    
    if args.all or args.plain:
        d.addCallback(lambda _: test_plain_bind(args.host, args.port))
        d.addErrback(onError)
    
    if args.all or args.starttls:
        d.addCallback(lambda _: test_starttls_bind(args.host, args.port))
        d.addErrback(onError)
    
    if args.all or args.ldaps:
        d.addCallback(lambda _: test_ldaps_bind(args.host, args.ldaps_port))
        d.addErrback(onError)
    
    return d


if __name__ == "__main__":
    react(main, sys.argv[1:])
