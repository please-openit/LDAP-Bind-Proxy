#!/usr/bin/env python
"""Quick test script using ldaptor to verify search functionality."""

from twisted.internet import defer, reactor
from twisted.internet.endpoints import clientFromString, connectProtocol
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols import pureldap

LDAP_HOST = "localhost"
LDAP_PORT = 389
BINDDN = b"cn=test,ou=people,dc=example,dc=org"
BINDPW = b"pwtest"
BASEDN = b"ou=people,dc=example,dc=org"

@defer.inlineCallbacks
def test_search():
    """Test bind and search operations."""
    try:
        # Connect
        endpoint_str = f"tcp:host={LDAP_HOST}:port={LDAP_PORT}"
        endpoint = clientFromString(reactor, endpoint_str)
        
        print("Connecting...")
        client = LDAPClient()
        proto = yield connectProtocol(endpoint, client)
        print("✓ Connected")
        
        # Bind
        print(f"Binding as: {BINDDN.decode('utf-8')}")
        yield client.bind(BINDDN, BINDPW)
        print("✓ Bind successful")
        
        # Search
        print(f"\nSearching base={BASEDN.decode('utf-8')}")
        
        # Create search request
        search_filter = pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=b'uid',
                assertionValue=b'test'
            ),
            pureldap.LDAPFilter_equalityMatch(
                attributeDesc=b'objectclass',
                assertionValue=b'inetOrgPerson'
            )
        ])
        
        req = pureldap.LDAPSearchRequest(
            baseObject=BASEDN,
            scope=pureldap.LDAP_SCOPE_wholeSubtree,
            derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
            sizeLimit=0,
            timeLimit=10,  # 10 second timeout
            typesOnly=False,
            filter=search_filter,
            attributes=[b'uid', b'cn', b'mail', b'sn', b'objectClass']
        )
        
        print("Sending search request...")
        response = yield client.send(req)
        print(f"✓ Got response: {response}")
        
        # Process results
        entries_found = 0
        while True:
            item = yield client.fetch_one_entry()
            if item is None:
                break
            if isinstance(item, pureldap.LDAPSearchResultEntry):
                entries_found += 1
                print(f"\nEntry {entries_found}: {item.objectName.decode('utf-8')}")
                for attr_name, attr_values in item.attributes:
                    values = [v.decode('utf-8') if isinstance(v, bytes) else str(v) for v in attr_values]
                    print(f"  {attr_name.decode('utf-8')}: {values}")
        
        print(f"\n✓ Search completed, found {entries_found} entries")
        
        yield client.unbind()
        print("✓ Test completed successfully\n")
        
    except Exception as ex:
        print(f"\n✗ Test FAILED: {repr(ex)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    from twisted.internet.task import react
    react(lambda reactor: test_search())
