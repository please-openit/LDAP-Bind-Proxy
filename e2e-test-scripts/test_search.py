#!/usr/bin/env python
"""Quick test script to verify search functionality."""

import ldap
import sys

# Connect to LDAP
try:
    print("Connecting to LDAP...")
    conn = ldap.initialize('ldap://localhost:389')
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    
    print("Binding as cn=test,ou=people,dc=example,dc=org...")
    conn.simple_bind_s('cn=test,ou=people,dc=example,dc=org', 'pwtest')
    print("✓ Bind successful")
    
    print("\nSearching for (uid=test)...")
    result = conn.search_s(
        'ou=people,dc=example,dc=org',
        ldap.SCOPE_SUBTREE,
        '(uid=test)',
        ['uid', 'cn', 'mail', 'sn']
    )
    
    print(f"✓ Search returned {len(result)} entries")
    for dn, attrs in result:
        print(f"\nDN: {dn}")
        for attr, values in attrs.items():
            print(f"  {attr}: {values}")
    
    conn.unbind_s()
    print("\n✓ Test completed successfully")
    
except ldap.LDAPError as e:
    print(f"\n✗ LDAP Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
