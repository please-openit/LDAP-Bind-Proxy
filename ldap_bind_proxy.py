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

import hashlib
import json
import os
import ssl
import sys
from datetime import datetime, timedelta

import jwt
import requests
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors, ldapserver
from OpenSSL import SSL, crypto
from twisted.internet import defer, protocol, reactor
from twisted.internet import ssl as twisted_ssl
from twisted.internet.ssl import (Certificate, CertificateOptions,
                                  PrivateCertificate)
from twisted.python import log


class Configuration():
    """
    Configuration class to hold environment variable values.
    Reads configuration from environment variables on initialization.

    OIDC Configuration:
    1. LDAP_PROXY_TOKEN_URL : OIDC Token endpoint URL
    2. LDAP_PROXY_CLIENT_ID : OIDC Client ID
    3. LDAP_PROXY_CLIENT_SECRET : OIDC Client Secret

    TLS Configuration:
    1. LDAP_PROXY_TLS_CERTFILE : Path to TLS certificate file for LDAPS (default None)
    2. LDAP_PROXY_TLS_KEYFILE : Path to TLS key file for LDAPS (default None)
    3. LDAP_PROXY_TLS_PORT : Port number for LDAPS listener (default 636)
    4. LDAP_PROXY_PORT : Port number for plain LDAP listener (default 389)
    5. LDAP_PROXY_ENABLE_PLAIN : Enable plain LDAP when TLS is configured (default false)
    6. LDAP_PROXY_TLS_CAFILE : Path to CA bundle for client certificate verification (default None)
    7. LDAP_PROXY_REQUIRE_CLIENT_CERT : Require client certificate for mTLS (default false)
    8. LDAP_PROXY_REQUIRE_SECURE_BIND : Reject credentialed binds on connections
       that are not encrypted (i.e. not LDAPS and not yet upgraded via
       STARTTLS) (default true). Set to false to allow plaintext binds on
       the plain LDAP listener (port 389 by default) - useful for local
       testing or trusted networks, but credentials will be sent in the
       clear.

    Directory Configuration:
    1. LDAP_PROXY_BASE_DN : Base DN for directory (default dc=example,dc=org)
    2. LDAP_PROXY_DOMAIN : Domain name for Windows compatibility (default example.org)


    """
    def __init__(self):
        # TLS configuration
        self.tls_certfile = os.environ.get('LDAP_PROXY_TLS_CERTFILE')
        self.tls_keyfile = os.environ.get('LDAP_PROXY_TLS_KEYFILE')
        self.tls_cafile = os.environ.get('LDAP_PROXY_TLS_CAFILE')
        self.tls_port = int(os.environ.get('LDAP_PROXY_TLS_PORT', '636'))
        self.plain_port = int(os.environ.get('LDAP_PROXY_PORT', '389'))
        self.enable_plain = os.environ.get('LDAP_PROXY_ENABLE_PLAIN', 'false').lower() in ('1', 'true', 'yes')
        self.require_client_cert = os.environ.get('LDAP_PROXY_REQUIRE_CLIENT_CERT', 'false').lower() in ('1', 'true', 'yes')
        self.require_secure_bind = os.environ.get('LDAP_PROXY_REQUIRE_SECURE_BIND', 'true').lower() in ('1', 'true', 'yes')

        # OIDC configuration
        self.url = os.environ.get("LDAP_PROXY_TOKEN_URL")
        self.client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
        self.client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")
        
        # Directory configuration
        self.base_dn = os.environ.get("LDAP_PROXY_BASE_DN", "dc=example,dc=org")
        self.domain = os.environ.get("LDAP_PROXY_DOMAIN", "example.org")

        # Fail closed: if mTLS is required, a CA file to verify client certs
        # against MUST be present. Silently downgrading to server-only TLS
        # when misconfigured would be a security regression, so refuse to
        # start instead.
        if self.require_client_cert and not self.tls_cafile:
            raise ValueError(
                "LDAP_PROXY_REQUIRE_CLIENT_CERT is enabled but "
                "LDAP_PROXY_TLS_CAFILE is not set. Refusing to start with "
                "mTLS silently disabled."
            )


class OidcProxy(ldapserver.BaseLDAPServer):
    """
    LDAP to OIDC authentication proxy with TLS support.
    
    This is a terminating proxy that translates LDAP bind requests to OIDC
    password grant requests. Unlike ProxyBase, we don't forward to a backend
    LDAP server - we handle all requests directly.
    
    Supports:
    - LDAPS (implicit TLS on port 636)
    - STARTTLS (explicit TLS upgrade on port 389)
    - mTLS (mutual TLS with client certificate verification)
    - LDAP search with user data from OIDC token claims
    """
    
    # Class-level token cache (shared across all connections)
    # Key: username, Value: {token_data, expires_at}
    _token_cache = {}
    
    def __init__(self, config, ssl_context_factory=None, connection_is_secure=False):
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config
        self.ssl_context_factory = ssl_context_factory
        self.startTLS_initiated = False
        self.bound_user = None  # Track currently bound user for this connection
        # Whether this connection is already protected by transport security
        # (i.e. it originated on the implicit-TLS/LDAPS listener). Connections
        # on the plain listener start False and flip to True only after a
        # successful STARTTLS upgrade.
        self.connection_is_secure = connection_is_secure

    def handleUnknown(self, request, controls, reply):
        """
        Handle incoming LDAP requests and translate to OIDC.
        
        This is the default handler for BaseLDAPServer when no specific
        handle_XXX method exists. We override it to handle bind, search,
        and unbind requests directly without forwarding to a backend.
        
        Note: STARTTLS is handled by handle_LDAPExtendedRequest.
        """
        # NOTE: do not log repr(request) here - LDAPBindRequest carries the
        # bind password in cleartext and would otherwise end up in logs.
        print(f"Received request: {request.__class__.__name__}")
        
        if isinstance(request, pureldap.LDAPBindRequest):
            # Handle anonymous bind (empty DN and password) for Root DSE access
            if not request.dn or request.dn == b'':
                # Anonymous bind - always succeed
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    matchedDN=b'',
                    errorMessage=b'',
                )
                reply(msg)
                return None

            # Refuse to process a credentialed bind over an unencrypted
            # channel, unless explicitly allowed via
            # LDAP_PROXY_REQUIRE_SECURE_BIND=false. This prevents passwords
            # from being sent in the clear when plain LDAP is enabled but
            # the client never issues STARTTLS.
            if not self.connection_is_secure and self.config.require_secure_bind:
                print("Rejecting bind: connection is not encrypted "
                      "(use LDAPS or STARTTLS first, or set "
                      "LDAP_PROXY_REQUIRE_SECURE_BIND=false to allow plaintext binds)")
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPConfidentialityRequired.resultCode,
                    matchedDN=b'',
                    errorMessage=b'Confidentiality required: use LDAPS or STARTTLS before binding',
                )
                reply(msg)
                return None
            elif not self.connection_is_secure:
                print("Warning: processing bind over unencrypted connection "
                      "(LDAP_PROXY_REQUIRE_SECURE_BIND=false) - credentials "
                      "are being sent in the clear")
            
            # Get OIDC token throught password grant
            # Extract username from DN (handle both cn=xxx and uid=xxx)
            rdn = request.dn.split(b',')[0]  # Get first RDN (e.g., "cn=test" or "uid=test")
            if b'=' in rdn:
                username = rdn.split(b'=', 1)[1]  # Get value after first '='
            else:
                username = rdn  # Fallback if no '=' found
            password = request.auth

            ## TODO : Nice to have Add support for OTP within password

            url = self.config.url
            client_id = self.config.client_id
            client_secret = self.config.client_secret

            # Use requests' form-encoding (the `data=` dict) instead of
            # manual string interpolation. Building the body with
            # str.format() let username/password values containing '&' or
            # '=' inject extra form fields into the token request.
            payload = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'password',
                'username': username.decode('utf-8'),
                'password': password.decode('utf-8'),
            }
            print(f"Requesting token from OIDC provider for user: {username.decode('utf-8')}")
            oidc_response = requests.request("POST", url, data=payload)

            # Logging username and status code (never log the password)
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))
            
            if oidc_response.status_code == requests.codes['ok']:
                # Store token data for search operations
                try:
                    token_data = oidc_response.json()
                    # Decode access token to get claims (without verification for caching)
                    access_token = token_data.get('access_token')
                    if access_token:
                        # Decode without verification (we trust our own OIDC server)
                        claims = jwt.decode(access_token, options={"verify_signature": False})
                        # Cache token with expiry
                        expires_in = token_data.get('expires_in', 300)  # Default 5 minutes
                        self._token_cache[username.decode('utf-8')] = {
                            'claims': claims,
                            'token_data': token_data,
                            'expires_at': datetime.now() + timedelta(seconds=expires_in)
                        }
                        # Track bound user for this connection
                        self.bound_user = username.decode('utf-8')
                except Exception as e:
                    print(f"Warning: Could not cache token data: {e}")
                
                # LDAP Bind success - include matchedDN for RFC compliance
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    matchedDN=request.dn,  # Echo back the DN that was bound
                    errorMessage=b'',      # Empty on success per RFC 4511
                )
            else:
                # Invalid credentials
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
                    matchedDN=b'',         # Empty on error
                    errorMessage=b'Invalid credentials',
                )
            reply(msg)
        if isinstance(request, pureldap.LDAPSearchRequest):
            return self.handle_LDAPSearchRequest(request, controls, reply)
        if isinstance(request, pureldap.LDAPUnbindRequest):
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        return None

    def handleStartTLSRequest(self, request, controls, reply):
        """
        Override ldaptor's handleStartTLSRequest to add logging.
        Upgrade the connection to TLS using factory.options.
        """
        print("handleStartTLSRequest called")
        
        if self.startTLS_initiated:
            # Already in TLS mode
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.LDAPOperationsError.resultCode,
                errorMessage=b'TLS already established'
            )
            print("TLS already established. Responding with operationsError")
        elif not hasattr(self.factory, 'options') or self.factory.options is None:
            # TLS not configured
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.LDAPUnavailable.resultCode,
                errorMessage=b'STARTTLS not available'
            )
            print("STARTTLS not available. Responding with unavailable")
        else:
            # Start TLS on the connection
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            print("Sending STARTTLS success response")
            reply(msg)
            # Upgrade connection to TLS after sending response
            print("Upgrading transport to TLS...")
            self.transport.startTLS(self.factory.options)
            self.startTLS_initiated = True
            self.connection_is_secure = True
            print("STARTTLS negotiation successful, connection upgraded to TLS")
            # Set msg to None so parent doesn't send it again
            msg = None
        
        # Reply if we haven't already
        if msg is not None:
            reply(msg)
        
        return None

    def handle_LDAPSearchRequest(self, request, controls, reply):
        """
        Handle LDAP search requests by returning user data from cached OIDC token claims.
        
        This allows Keycloak (and other LDAP clients) to query user attributes
        after a successful bind operation.

        Authorization: a connection may only ever see the claims of the user
        that authenticated *on that connection* (self.bound_user). Looking up
        arbitrary usernames from the shared token cache based on the filter
        would let any bound (or even anonymous) client read other users'
        cached claims - this used to be possible and has been removed.
        
        Special handling:
        - Root DSE (base="") - Returns server capabilities for Windows AD compatibility
        - User searches - Returns user attributes from OIDC token claims
        - Base DN queries - Returns domain object information
        """
        print(f"Search request: base={request.baseObject}, scope={request.scope}")
        
        # Handle Root DSE query (empty base DN)
        if request.baseObject == b'' or request.baseObject == b'""':
            return self._handle_root_dse(request, controls, reply)

        # LDAP search scopes (RFC 4511): 0=baseObject, 1=singleLevel, 2=wholeSubtree
        SCOPE_BASE, SCOPE_ONE_LEVEL, SCOPE_SUBTREE = 0, 1, 2

        requested_base = self._normalize_dn(request.baseObject)
        configured_base = self._normalize_dn(self.config.base_dn)

        # Only ever serve data for the user bound on THIS connection. An
        # unauthenticated (anonymous-bound) connection has no bound_user and
        # gets nothing back.
        if self.bound_user and self.bound_user in self._token_cache:
            # If the search filter names a specific uid, it must match the
            # bound user - otherwise this would let a bound user query other
            # users' cached claims.
            requested_uid = self._extract_uid_from_filter(request.filter)
            if requested_uid is not None and requested_uid != self.bound_user:
                print(f"Denying search: bound user {self.bound_user} "
                      f"requested data for different uid {requested_uid}")
            else:
                cache_entry = self._token_cache[self.bound_user]
                # Check if token is still valid
                if cache_entry['expires_at'] > datetime.now():
                    user_dn = self._normalize_dn(
                        f"uid={self.bound_user},{self.config.base_dn}"
                    )
                    entry = None

                    if requested_base == user_dn and request.scope in (SCOPE_BASE, SCOPE_SUBTREE):
                        # Client is asking about the user's own entry directly
                        # (e.g. re-fetching after a search) - return it, with
                        # no fabricated children.
                        entry = self._create_search_entry(
                            self.bound_user, cache_entry['claims'], request.attributes
                        )
                    elif requested_base == configured_base and request.scope in (SCOPE_ONE_LEVEL, SCOPE_SUBTREE):
                        # Client is listing children of the configured base DN
                        # (e.g. expanding dc=example,dc=org in a browser) -
                        # return the single user entry as a child.
                        entry = self._create_search_entry(
                            self.bound_user, cache_entry['claims'], request.attributes
                        )
                    elif requested_base == configured_base and request.scope == SCOPE_BASE:
                        # Base-scope search directly on the container itself.
                        # The container isn't modeled as its own entry here,
                        # so there is nothing to return - not an error.
                        entry = None
                    else:
                        # Base DN doesn't match anything we know about (e.g. a
                        # one-level search under the user's own DN, which has
                        # no children). Returning nothing here - rather than
                        # fabricating a uid=test child under any base we're
                        # given - is what prevents clients from recursing
                        # into an infinitely nested fake tree.
                        print(f"No matching entry for base={requested_base} "
                              f"scope={request.scope}")
                        entry = None

                    if entry:
                        reply(entry)
                else:
                    print(f"Token expired for user {self.bound_user}")
                    # Clean up expired entry
                    del self._token_cache[self.bound_user]
        
        # Always send search done
        msg = pureldap.LDAPSearchResultDone(
            resultCode=ldaperrors.Success.resultCode
        )
        reply(msg)
        return None
    
    def _handle_root_dse(self, request, controls, reply):
        """
        Handle Root DSE query - returns server capabilities.
        This is critical for Windows clients to discover directory information.
        """
        print("Handling Root DSE query")
        
        base_dn_bytes = self.config.base_dn.encode('utf-8') if isinstance(self.config.base_dn, str) else self.config.base_dn
        
        root_dse_attrs = [
            (b'objectClass', [b'top']),
            (b'namingContexts', [base_dn_bytes]),
            (b'defaultNamingContext', [base_dn_bytes]),
            (b'supportedLDAPVersion', [b'3']),
            (b'supportedSASLMechanisms', [b'PLAIN']),
            (b'subschemaSubentry', [b'cn=schema']),
            (b'vendorName', [b'LDAP-OIDC-Proxy']),
            (b'vendorVersion', [b'1.0.0']),
            (b'supportedExtension', [
                b'1.3.6.1.4.1.1466.20037',  # STARTTLS
                b'1.3.6.1.4.1.4203.1.11.3',  # WhoAmI
            ]),
        ]
        
        entry = pureldap.LDAPSearchResultEntry(
            objectName=b'',
            attributes=root_dse_attrs
        )
        
        reply(entry)
        
        # Send search done
        msg = pureldap.LDAPSearchResultDone(
            resultCode=ldaperrors.Success.resultCode
        )
        reply(msg)
        return None
    
    def _normalize_dn(self, dn):
        """
        Normalize a DN (bytes or str) for comparison purposes: decode,
        strip surrounding whitespace/trailing commas, lowercase.
        This is intentionally simple (no RDN-aware escaping) since the
        DNs handled by this proxy are all generated by us in a fixed
        format.
        """
        if isinstance(dn, bytes):
            dn = dn.decode('utf-8')
        return dn.strip().rstrip(',').lower()

    def _extract_uid_from_filter(self, ldap_filter):
        """
        Extract uid (username) from LDAP filter.
        Handles filters like (&(uid=test)(objectclass=inetOrgPerson))
        """
        if not ldap_filter:
            return None
        
        # Handle AND filters
        if hasattr(ldap_filter, 'value') and isinstance(ldap_filter.value, list):
            for f in ldap_filter.value:
                uid = self._extract_uid_from_filter(f)
                if uid:
                    return uid
        
        # Handle equality match (uid=value)
        if hasattr(ldap_filter, 'attributeDesc') and hasattr(ldap_filter, 'assertionValue'):
            attr = ldap_filter.attributeDesc.value if hasattr(ldap_filter.attributeDesc, 'value') else ldap_filter.attributeDesc
            if attr == b'uid':
                value = ldap_filter.assertionValue.value if hasattr(ldap_filter.assertionValue, 'value') else ldap_filter.assertionValue
                return value.decode('utf-8') if isinstance(value, bytes) else value
        
        return None
    
    def _create_search_entry(self, username, claims, requested_attrs):
        """
        Create LDAP search result entry from OIDC token claims.
        
        Maps OIDC claims to LDAP attributes:
        - preferred_username/sub -> uid, sAMAccountName
        - email -> mail, userPrincipalName
        - name -> cn
        - family_name -> sn
        - given_name -> givenName
        - groups/roles -> memberOf

        The entry's DN is always built from the server's configured base
        DN (self.config.base_dn), never from the client-supplied search
        base. Previously the search base itself was concatenated in here,
        which meant every level a client "discovered" became a valid base
        for the next search, letting a browser recurse into an infinitely
        nested fake uid=test,uid=test,... tree.
        """
        base_dn = self.config.base_dn
        # Build DN for the user
        user_dn = f"uid={username},{base_dn.decode('utf-8') if isinstance(base_dn, bytes) else base_dn}"
        
        # Map OIDC claims to LDAP attributes
        attributes = []
        
        # objectClass - always return this (include user for Windows compatibility)
        attributes.append((b'objectClass', [b'inetOrgPerson', b'organizationalPerson', b'person', b'top', b'user']))
        
        # uid
        if b'uid' in requested_attrs or not requested_attrs:
            attributes.append((b'uid', [username.encode('utf-8')]))
        
        # sAMAccountName (Windows login name)
        if b'sAMAccountName' in requested_attrs or not requested_attrs:
            attributes.append((b'sAMAccountName', [username.encode('utf-8')]))
        
        # userPrincipalName (user@domain format for Windows)
        if b'userPrincipalName' in requested_attrs or not requested_attrs:
            upn = claims.get('email') or f"{username}@{self.config.domain}"
            attributes.append((b'userPrincipalName', [upn.encode('utf-8') if isinstance(upn, str) else upn]))
        
        # cn (common name)
        if b'cn' in requested_attrs or not requested_attrs:
            cn = claims.get('name') or claims.get('preferred_username') or username
            attributes.append((b'cn', [cn.encode('utf-8') if isinstance(cn, str) else cn]))
        
        # sn (surname)
        if b'sn' in requested_attrs or not requested_attrs:
            sn = claims.get('family_name') or username
            attributes.append((b'sn', [sn.encode('utf-8') if isinstance(sn, str) else sn]))
        
        # givenName
        if b'givenName' in requested_attrs or not requested_attrs:
            given_name = claims.get('given_name')
            if given_name:
                attributes.append((b'givenName', [given_name.encode('utf-8') if isinstance(given_name, str) else given_name]))
        
        # mail (email)
        if b'mail' in requested_attrs or not requested_attrs:
            email = claims.get('email')
            if email:
                attributes.append((b'mail', [email.encode('utf-8') if isinstance(email, str) else email]))
        
        # memberOf - group memberships from OIDC claims
        if b'memberOf' in requested_attrs or not requested_attrs:
            groups = self._extract_groups_from_claims(claims, base_dn)
            if groups:
                attributes.append((b'memberOf', groups))
        
        # objectSid - Windows Security Identifier (generated from username)
        if b'objectSid' in requested_attrs or not requested_attrs:
            sid = self._generate_sid(username)
            attributes.append((b'objectSid', [sid]))
        
        # primaryGroupID - RID of primary group (Domain Users = 513)
        if b'primaryGroupID' in requested_attrs or not requested_attrs:
            attributes.append((b'primaryGroupID', [b'513']))
        
        # userAccountControl - account flags (normal account = 512)
        if b'userAccountControl' in requested_attrs or not requested_attrs:
            attributes.append((b'userAccountControl', [b'512']))
        
        # entryUUID - generate from username
        if b'entryUUID' in requested_attrs or not requested_attrs:
            # Generate a deterministic UUID from username
            uuid_hash = hashlib.md5(username.encode('utf-8')).hexdigest()
            uuid_formatted = f"{uuid_hash[:8]}-{uuid_hash[8:12]}-{uuid_hash[12:16]}-{uuid_hash[16:20]}-{uuid_hash[20:32]}"
            attributes.append((b'entryUUID', [uuid_formatted.encode('utf-8')]))
        
        # createTimestamp and modifyTimestamp
        if b'createTimestamp' in requested_attrs or b'modifyTimestamp' in requested_attrs or not requested_attrs:
            # Use iat (issued at) from token if available
            timestamp = claims.get('iat')
            if timestamp:
                dt = datetime.fromtimestamp(timestamp)
                ldap_time = dt.strftime('%Y%m%d%H%M%SZ')
                if b'createTimestamp' in requested_attrs or not requested_attrs:
                    attributes.append((b'createTimestamp', [ldap_time.encode('utf-8')]))
                if b'modifyTimestamp' in requested_attrs or not requested_attrs:
                    attributes.append((b'modifyTimestamp', [ldap_time.encode('utf-8')]))
        
        # Filter attributes if specific ones were requested
        if requested_attrs:
            filtered_attrs = []
            for attr_name, attr_values in attributes:
                if attr_name in requested_attrs or attr_name == b'objectClass':
                    filtered_attrs.append((attr_name, attr_values))
            attributes = filtered_attrs
        
        # Create and return search result entry
        entry = pureldap.LDAPSearchResultEntry(
            objectName=user_dn.encode('utf-8') if isinstance(user_dn, str) else user_dn,
            attributes=attributes
        )
        
        print(f"Returning search entry for {user_dn}")
        return entry
    
    def _extract_groups_from_claims(self, claims, base_dn):
        """
        Extract group/role memberships from OIDC token claims and map them
        to memberOf DNs, distinguishing groups from roles by OU:

        - claims['groups']                     -> cn=<name>,ou=groups,<base>
        - claims['realm_access']['roles']       -> cn=<name>,ou=roles,<base>
        - claims['resource_access'][*]['roles'] -> cn=<name>,ou=roles,<base>
          (iterated for every client present under resource_access)
        """
        groups = []
        seen = set()
        base_dn_str = base_dn.decode('utf-8') if isinstance(base_dn, bytes) else base_dn

        def add_all(names, ou):
            for name in names:
                if isinstance(name, str):
                    key = (ou, name)
                    if key not in seen:
                        seen.add(key)
                        group_dn = f"cn={name},ou={ou},{base_dn_str}"
                        groups.append(group_dn.encode('utf-8'))

        # groups claim -> ou=groups
        add_all(claims.get('groups', []) or [], 'groups')

        # realm_access.roles -> ou=roles
        realm_access = claims.get('realm_access') or {}
        if isinstance(realm_access, dict):
            add_all(realm_access.get('roles', []) or [], 'roles')

        # resource_access.<client>.roles -> ou=roles, iterate every client entry
        resource_access = claims.get('resource_access') or {}
        if isinstance(resource_access, dict):
            for client_id, client_claims in resource_access.items():
                if isinstance(client_claims, dict):
                    add_all(client_claims.get('roles', []) or [], 'roles')

        # Always add Domain Users group for Windows compatibility
        domain_users_dn = f"cn=Domain Users,ou=groups,{base_dn_str}"
        groups.append(domain_users_dn.encode('utf-8'))

        return groups if groups else None
    
    def _generate_sid(self, username):
        """
        Generate a Windows-compatible SID (Security Identifier) from username.
        Format: S-1-5-21-<domain>-<domain>-<domain>-<RID>
        
        This is a deterministic generation for consistency.
        Real AD would have actual domain SIDs.
        """
        # Generate deterministic domain identifier parts from username hash
        domain_hash = hashlib.md5(self.config.domain.encode('utf-8')).hexdigest()
        domain_id_1 = int(domain_hash[0:8], 16) % 4294967295
        domain_id_2 = int(domain_hash[8:16], 16) % 4294967295
        domain_id_3 = int(domain_hash[16:24], 16) % 4294967295
        
        # Generate RID (Relative ID) from username
        user_hash = hashlib.md5(username.encode('utf-8')).hexdigest()
        rid = 1000 + (int(user_hash[0:8], 16) % 100000)  # RID range 1000-101000
        
        # Format SID string
        sid = f"S-1-5-21-{domain_id_1}-{domain_id_2}-{domain_id_3}-{rid}"
        return sid.encode('utf-8')

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        """
        Handle LDAP Extended Request - intercepts STARTTLS before parent class.
        Uses defer.maybeDeferred like the parent class.
        """
        print(f"handle_LDAPExtendedRequest called: {request.requestName if hasattr(request, 'requestName') else 'unknown'}")
        
        # Check if this is a STARTTLS request
        if hasattr(request, 'requestName') and request.requestName == pureldap.LDAPStartTLSRequest.oid:
            # Call handleStartTLSRequest with defer like parent does
            from twisted.internet import defer
            d = defer.maybeDeferred(
                self.handleStartTLSRequest, request, controls, reply
            )
            d.addErrback(lambda err: print(f"STARTTLS error: {err}"))
            return d
        
        # For other extended operations, return success dummy response
        msg = pureldap.LDAPExtendedResponse(
            resultCode=ldaperrors.Success.resultCode
        )
        reply(msg)
        return None


def create_ssl_context_factory(config):
    """
    Create an SSL context factory with support for mTLS and CA validation.
    
    Args:
        config: Configuration object with TLS settings
    
    Returns:
        CertificateOptions object for Twisted SSL
    """
    if not config.tls_certfile or not config.tls_keyfile:
        return None
    
    try:
        # Load server certificate and private key
        with open(config.tls_certfile, 'rb') as cert_file:
            cert_data = cert_file.read()
        with open(config.tls_keyfile, 'rb') as key_file:
            key_data = key_file.read()
        
        # Create certificate object
        certificate = PrivateCertificate.loadPEM(cert_data + key_data)
        
        # Configure SSL context
        extra_options = []
        
        # Disable SSL v2 and v3, use only TLS
        extra_options.append(SSL.OP_NO_SSLv2)
        extra_options.append(SSL.OP_NO_SSLv3)
        
        # Configure client certificate verification if mTLS is enabled
        if config.require_client_cert:
            # Configuration.__init__ already guarantees tls_cafile is set
            # whenever require_client_cert is True (fails closed otherwise),
            # so we don't need to silently fall back here anymore.
            # Load CA certificate for client verification
            with open(config.tls_cafile, 'rb') as ca_file:
                ca_cert_data = ca_file.read()
            
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_data)
            
            # Create certificate options with client cert verification
            # Note: trustRoot alone enables client certificate verification in Twisted
            # requireCertificate is deprecated and mutually exclusive with trustRoot
            context_factory = CertificateOptions(
                privateKey=certificate.privateKey.original,
                certificate=certificate.original,
                trustRoot=twisted_ssl.trustRootFromCertificates([Certificate(ca_cert)]),
                extraCertChain=[],
            )
            print(f"mTLS enabled: client certificates will be verified against CA: {config.tls_cafile}")
        else:
            # Server-only TLS (no client cert verification)
            context_factory = CertificateOptions(
                privateKey=certificate.privateKey.original,
                certificate=certificate.original,
                extraCertChain=[],
            )
            if config.tls_cafile:
                print(f"Note: CA file specified but client cert verification not required (LDAP_PROXY_REQUIRE_CLIENT_CERT=false)")
        
        return context_factory
    
    except Exception as e:
        print(f"Error creating SSL context: {e}")
        raise
    
if __name__ == '__main__':
    """
    Demonstration LDAP OIDC proxy with TLS support.
    Supports LDAPS (implicit TLS), STARTTLS (explicit TLS), and mTLS.
    """

    config = Configuration()

    log.startLogging(sys.stderr)
    
    # Create SSL context factory if TLS is configured
    ssl_context_factory = create_ssl_context_factory(config)

    # ---- Plain (port 389) listener factory ----
    # Connections here start out NOT secure; they only become secure once
    # STARTTLS succeeds. Credentialed binds are rejected until then.
    plain_factory = protocol.ServerFactory()
    plain_factory.options = ssl_context_factory  # needed for STARTTLS support

    def build_plain_protocol():
        return OidcProxy(config, ssl_context_factory, connection_is_secure=False)

    plain_factory.protocol = build_plain_protocol

    # ---- LDAPS (implicit TLS) listener factory ----
    # Connections here are secure from the moment they're established.
    tls_factory = protocol.ServerFactory()
    tls_factory.options = ssl_context_factory

    def build_tls_protocol():
        return OidcProxy(config, ssl_context_factory, connection_is_secure=True)

    tls_factory.protocol = build_tls_protocol

    # Configure listeners based on TLS settings
    listeners_started = []
    
    # Start plain LDAP listener
    if config.enable_plain or not ssl_context_factory:
        try:
            reactor.listenTCP(config.plain_port, plain_factory)
            listeners_started.append(f'Plain LDAP on port {config.plain_port}')
            print(f'Plain LDAP listening on port {config.plain_port}')
        except Exception as e:
            print(f'Warning: Failed to start plain LDAP listener: {e}')

    if config.tls_certfile and config.tls_keyfile and ssl_context_factory:
        # Start LDAPS listener (implicit TLS on port 636)
        try:
            reactor.listenSSL(config.tls_port, tls_factory, ssl_context_factory)
            listeners_started.append(f'LDAPS on port {config.tls_port}')
            print(f'LDAPS listening on port {config.tls_port}')
        except Exception as e:
            print(f'Failed to start LDAPS: {e}')
            print(f'Exiting. Please check your TLS certificate and key file paths and port {config.tls_port} availability.')
            sys.exit(1)
    
    if not listeners_started:
        print('Error: No listeners could be started. Exiting.')
        sys.exit(1)
    
    print(f'LDAP proxy started with listeners: {", ".join(listeners_started)}')
    reactor.run()