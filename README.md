


# Get rid of your old Active directory/LDAP with keycloak and a small piece of custom software

## TL;DR

How to spawn a simple LDAP proxy for Keycloak OIDC integration. Supports LDAP bind authentication and search operations, with production-ready TLS/SSL support including LDAPS, STARTTLS, and mTLS.

## ✨ Features

- **LDAP Authentication** - Translates LDAP bind requests to OIDC password grants
- **LDAP Search** - Returns user attributes from OIDC token claims
- **Windows AD Compatibility** - Root DSE, sAMAccountName, userPrincipalName, objectSid, memberOf
- **Group Membership** - Maps OIDC groups/roles to LDAP group DNs
- **TLS/SSL Support** - LDAPS, STARTTLS, and mTLS for secure connections
- **Keycloak Integration** - Works with Keycloak LDAP federation for legacy applications
- **Read-Only** - Secure proxy that doesn't modify the identity provider

## 🔒 TLS/SSL Support (NEW)

LDAP-Bind-Proxy now supports comprehensive TLS encryption:

- **LDAPS** - Implicit TLS on port 636 (recommended for production)
- **STARTTLS** - Explicit TLS upgrade on port 389
- **mTLS** - Mutual TLS with client certificate verification
- **CA Validation** - Custom CA certificate support

📖 **[Read the complete TLS Configuration Guide](TLS-GUIDE.md)**

### Quick TLS Setup

```bash
# Generate certificate (testing only)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=localhost"

# Configure and start with LDAPS
export LDAP_PROXY_TLS_CERTFILE=./server.crt
export LDAP_PROXY_TLS_KEYFILE=./server.key
export LDAP_PROXY_TOKEN_URL=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token
export LDAP_PROXY_CLIENT_ID=ldap-proxy
export LDAP_PROXY_CLIENT_SECRET=your-secret

python ldap_bind_proxy.py
# LDAPS listening on port 636
```

## Disclaimer and license

The principles and code presented here are only a proof of concept and shouldn't be used in production as is. Use it at your own risks. If you see any problem with the concept or its implementation feel free to open an issue or submit a pull request on github. [https://github.com/please-openit/LDAP-Bind-Proxy](https://github.com/please-openit/LDAP-Bind-Proxy)

This proof of concept is distributed under the Apache 2.0 license. See LICENSE.md in the git repository.

## LDAP/AD is more and more a legacy service but not always

If you are using Active directory as your main user management tool and are happy with it this article may not be meant for you.
There is no problem with using Active directory or LDAP at the core of your system, this article is meant for those who have to deal with one or two legacy software supporting only LDAP protocol.

In such a case, the common way to do it with keycloak is to use an OpenLDAP as the keycloak user backend. This allows to enable both OpenId Connect and LDAP but it has major drawbacks. If OpenLDAP fails keycloak also fails, it is a new single point of failure to your infrastructure. Thus there is the need to maintain and replicate this element. This can be a lot of work sometimes only to maintain compatibility with a non critical legacy application.

![Old configuration with two spofs](image.png)

## An elegant minimalist LDAP proxy for keycloak

To deal with the situation described above, it would be nice to have a minimalist proxy to perform and translate LDAP bind request against the keycloak server. 


Keycloak implements the OpenID Connect direct password grant, this allows us to imagine a simpler and more robust architecture.

![New architecture with one spof](image-1.png)

There are the same number of components but the LDAP proxy is stateless and less critical depending on the applications that rely on it.

It is also a way more simple component that can be spawned anywhere you need it even besides your client application for casual use.

## How LDAP Bind proxy works

The LDAP Bind Proxy acts as a terminating LDAP server that translates LDAP operations to OIDC:

**Authentication (LDAP Bind):**
- Receives LDAP bind request with username/password
- Translates to OIDC password grant request
- Caches OIDC access token claims on successful authentication
- Returns RFC 4511 compliant LDAP bind response

**Directory Queries (LDAP Search):**
- Receives LDAP search requests
- Returns user attributes from cached OIDC token claims
- Maps OIDC claims to standard LDAP attributes (uid, mail, cn, sn, etc.)

![Sequence diagram of LDAP Bind proxy](image-2.png)

The user logs-in as usual, the legacy app sends LDAP requests as it always does, and the proxy translates them to OIDC operations, returning LDAP responses based on Keycloak's OIDC responses.

### Supported LDAP Operations

- **Bind** - Authentication via OIDC password grant
- **Search** - User attribute queries from OIDC token claims  
- **Unbind** - Session cleanup
- **STARTTLS** - TLS upgrade for secure connections

### OIDC Claim to LDAP Attribute Mapping

| OIDC Claim | LDAP Attribute | Description |
|------------|----------------|-------------|
| preferred_username/sub | uid | User ID |
| email | mail | Email address |
| name | cn | Common name (full name) |
| family_name | sn | Surname (last name) |
| given_name | givenName | First name |
| iat | createTimestamp | Account creation time |
| iat | modifyTimestamp | Last modification time |
| (generated) | entryUUID | Unique entry identifier |
| (static) | objectClass | inetOrgPerson, organizationalPerson, person, top, user |

### Windows Active Directory Attributes

For Windows domain login compatibility, additional AD-specific attributes are provided:

| OIDC Claim | LDAP Attribute | Description |
|------------|----------------|-------------|
| preferred_username | sAMAccountName | Windows login name |
| email | userPrincipalName | UPN format (user@domain) |
| groups/roles | memberOf | Group DN list |
| (generated) | objectSid | Windows Security Identifier |
| (static) | primaryGroupID | Primary group RID (513 = Domain Users) |
| (static) | userAccountControl | Account control flags (512 = normal account) |

### Root DSE Support

The proxy responds to Root DSE queries (empty base DN) with server capabilities, essential for Windows clients to discover the directory:

- `namingContexts` - Available directory partitions
- `defaultNamingContext` - Default base DN
- `supportedLDAPVersion` - LDAP version 3
- `supportedSASLMechanisms` - Authentication mechanisms
- `supportedExtension` - Extended operations (STARTTLS, WhoAmI)

To ensure login security, the client must be confidential and the LDAP bind proxy must be deployed on a safe network and VM to keep its client credentials secret.

## Implementation

A full demo is available on github, feel free to try it by yourself. [https://github.com/please-openit/LDAP-Bind-Proxy](https://github.com/please-openit/LDAP-Bind-Proxy)

The proof of concept relies on LDAPProxy from twisted/ldaptor for convenience reasons. But could have been built on top of any up-to-date LDAP layer.

All parameters comes from environment variables with all standard names you already knows.

- LDAP_PROXY_TOKEN_URL
- LDAP_PROXY_CLIENT_ID
- LDAP_PROXY_CLIENT_SECRET


Here is the core part of the code doing the main operation :

```python
            # Get username and password from LDAPBind request
            username = request.dn.split(b',')[0][3:]
            password = request.auth

            
            # Url of the token endpoint of OIDC provider
            url = os.environ.get("LDAP_PROXY_TOKEN_URL")
            client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
            client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")

            # Payload of the password grant request
            payload = 'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={username}&password={password}'.format(client_id=client_id, client_secret=client_secret, username=username.decode('utf-8'), password=password.decode('utf-8'))
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }

            # Doing le password grand request
            oidc_response = requests.request("POST", url, headers=headers, data=payload)

            # Logging username and status code
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))


            # Build a LDAPBindResponse, succes or failure depending of the status code of the password grant request
            if oidc_response.status_code == requests.codes['ok']:
                # LDAP Bind success
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Invalid credentials LDAP error 49 (see keycloak logs for details)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
```

The operation used (grant_type=password) is the same as described in oidc-bash.sh : [https://github.com/please-openit/oidc-bash-client/blob/master/oidc-client.sh#L33](https://github.com/please-openit/oidc-bash-client/blob/master/oidc-client.sh#L33)


Interesting note on implementation of this poc :

The library used is designed to forward its requests to a backend LDAP server. In this case we don't want that to occur so the LDAPClient object handling upstream LDAP communication is replaced by a Mock object. A cleaner implementation using the same library is possible.

```python
    ## TODO: This is a Workaround, implement a cleaner proxy class from class ServerBase
    def connectionMade(self):
        """ Overridden method to prevent proxy from trying to connect non-existing backend server.
        Mocking client class to drop every operation made to it"""
        print("connectionMade called")
        self.client = Mock()
        ldapserver.BaseLDAPServer.connectionMade(self)
```

## Proof of concept usage

Build and start keycloak and LDAP Bind proxy from `docker compose`.

```bash
docker compose up -d --build
```

Test with `python ./ldap_client_bind.py` or any client you want.
The test binddn and the test password are the followings :
* Bind DN : cn=test,ou=people,dc=example,dc=org
* Password : pwtest

In fact in this configuration **only the CN part of the Bind DN is important** and used as username.
You can even try by yourself to create another user in keycloak (admin/admin for admin console), in that case you must login for the first time through the account console of keycloak. Any required action on the account or temporary password will block password grant. Login into the account console is the most straightforward way to ensure everything is fine.

Example using ldap-utils ldapwhoami :

```bash
$ ldapwhoami -D "cn=test,ou=people,dc=example,dc=org" -w pwtest; echo $?
0
```
In this case `ldapwhoami` sends a `LDAPExtendedRequest` to get details and the proxy response is an empty ``LDAPExtendedResponse`. Therefore there is nothing printed in the output of the command but the return code is 0 and the log of the proxy indicates a successful bind. It would be nice in the future to map some information from IDtoken to the `LDAPExtendedResponse`

Example using ldap-utils ldapsearch :

```bash
$ ldapsearch -x -D 'cn=test,ou=people,dc=example,dc=org' -w pwtest
# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 0 Success

# numResponses: 1
```

`ldapsearch` has a more verbose output despite the fact it receives an empty `LDAPSearchResultDone`. Maybe better for testing.

Only the LDAPBindRequest is really supported, other replies are empty dummies, this will be enough for login operation but don't expect showing anything in an LDAP admin tool for now.

## Keycloak configuration

A client (with authentication) is needed. No "standard flow", of course no URI in configuration. Just "Direct access grant" enabled.

![Direct acces grant configuration](image-3.png)

## Testing

### Unit Tests

Comprehensive test coverage for TLS features:

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Run unit tests
python -m pytest tests/test_tls_support.py -v

# Run with coverage report
python -m pytest tests/test_tls_support.py --cov=ldap_bind_proxy --cov-report=html
```

### Integration Tests

Test real TLS connections:

```bash
# Generate test certificates
python tests/test_integration.py --generate-certs ./certs

# Set environment and start proxy
export LDAP_PROXY_TLS_CERTFILE=./certs/server.crt
export LDAP_PROXY_TLS_KEYFILE=./certs/server.key
export LDAP_PROXY_ENABLE_PLAIN=true
export LDAP_PROXY_ENABLE_STARTTLS=true
# ... set OIDC vars ...
python ldap_bind_proxy.py &

# Run integration tests
python tests/test_integration.py --all
```

Test results show:
- ✓ LDAPS connection on port 636
- ✓ STARTTLS negotiation on port 389
- ✓ Certificate validation
- ✓ mTLS client certificate verification

## Conclusion/Going further

This piece of code and documentation demonstrate the opportunity of such an architecture. The possibility to save a lot of time in MOC by not having to maintain an LDAP service which is often poorly integrated with modern cloud platform.

### ✅ Production-Ready Features

The following features are now production-ready:

* ✅ **TLS/SSL encryption** - LDAPS, STARTTLS, and mTLS support
* ✅ **Certificate validation** - CA verification and client certificates
* ✅ **Comprehensive test coverage** - Unit and integration tests
* ✅ **Security hardening** - Modern TLS versions, strong ciphers, PFS
* ✅ **Docker support** - Ready for containerized deployments
* ✅ **Environment-based configuration** - Easy deployment and configuration management

### 🚧 Future Enhancements

Features that would further enhance the proxy:

* Implement mapping with the token and a real ldapwhoami
* Add basic read-only search with Keycloak API integration
* Track LDAP sessions and keep OpenID tokens in a key-value cache store
* Implement real logout with token revocation
* Add metrics and monitoring (Prometheus/OpenTelemetry)
* Connection pooling and rate limiting
* High availability and load balancing support

