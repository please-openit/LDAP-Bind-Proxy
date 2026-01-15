#!/bin/bash
#
# Test script for LDAP-Bind-Proxy TLS modes using ldapwhoami
# Tests: Plain LDAP, STARTTLS, and LDAPS
#
# Usage: ./test_ldap_modes.sh [-v]
#   -v  Verbose mode: show ldapwhoami output
#

set -e

# Parse arguments
VERBOSE=false
if [[ "$1" == "-v" ]]; then
    VERBOSE=true
fi

# Configuration
HOST="localhost"
PLAIN_PORT="389"
LDAPS_PORT="636"
BINDDN="cn=test,ou=people,dc=example,dc=org"
BINDPW="pwtest"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Determine output redirection based on verbose flag
if $VERBOSE; then
    OUTPUT_REDIRECT=""
else
    OUTPUT_REDIRECT="2>/dev/null"
fi

echo ""
echo "=========================================="
echo "LDAP-Bind-Proxy TLS Mode Tests"
echo "=========================================="
echo ""

# Test 1: Plain LDAP (no encryption)
echo -e "${YELLOW}Test 1: Plain LDAP (no encryption)${NC}"
echo "Command: ldapwhoami -h $HOST -p $PLAIN_PORT -D \"$BINDDN\" -w $BINDPW"
if $VERBOSE; then
    if ldapwhoami -vvv -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW"; then
        echo -e "${GREEN}✓ Plain LDAP test PASSED${NC}"
    else
        echo -e "${RED}✗ Plain LDAP test FAILED${NC}"
    fi
else
    if ldapwhoami -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW" 2>/dev/null; then
        echo -e "${GREEN}✓ Plain LDAP test PASSED${NC}"
    else
        echo -e "${RED}✗ Plain LDAP test FAILED${NC}"
    fi
fi
echo ""

# Test 2: STARTTLS (explicit TLS upgrade)
echo -e "${YELLOW}Test 2: STARTTLS (explicit TLS upgrade)${NC}"
echo "Command: ldapwhoami -h $HOST -p $PLAIN_PORT -D \"$BINDDN\" -w $BINDPW -ZZ"
if $VERBOSE; then
    if ldapwhoami -vvv -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW" -ZZ; then
        echo -e "${GREEN}✓ STARTTLS test PASSED${NC}"
    else
        echo -e "${RED}✗ STARTTLS test FAILED (use LDAPTLS_REQCERT=never if using self-signed certs)${NC}"
    fi
else
    if ldapwhoami -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW" -ZZ 2>/dev/null; then
        echo -e "${GREEN}✓ STARTTLS test PASSED${NC}"
    else
        echo -e "${RED}✗ STARTTLS test FAILED (use LDAPTLS_REQCERT=never if using self-signed certs)${NC}"
    fi
fi
echo ""

# Test 3: LDAPS (implicit TLS)
echo -e "${YELLOW}Test 3: LDAPS (implicit TLS on port $LDAPS_PORT)${NC}"
echo "Command: ldapwhoami -h $HOST -p $LDAPS_PORT -D \"$BINDDN\" -w $BINDPW -H ldaps://$HOST:$LDAPS_PORT"
if $VERBOSE; then
    if ldapwhoami -vvv -H "ldaps://$HOST:$LDAPS_PORT" -D "$BINDDN" -w "$BINDPW"; then
        echo -e "${GREEN}✓ LDAPS test PASSED${NC}"
    else
        echo -e "${RED}✗ LDAPS test FAILED (use LDAPTLS_REQCERT=never if using self-signed certs)${NC}"
    fi
else
    if ldapwhoami -H "ldaps://$HOST:$LDAPS_PORT" -D "$BINDDN" -w "$BINDPW" 2>/dev/null; then
        echo -e "${GREEN}✓ LDAPS test PASSED${NC}"
    else
        echo -e "${RED}✗ LDAPS test FAILED (use LDAPTLS_REQCERT=never if using self-signed certs)${NC}"
    fi
fi
echo ""

echo "=========================================="
echo "Testing with LDAPTLS_REQCERT=never (accept self-signed certificates)"
echo "=========================================="
echo ""

# Test with certificate verification disabled
export LDAPTLS_REQCERT=never

# Test 2 retry: STARTTLS with cert verification disabled
echo -e "${YELLOW}Test 2 (retry): STARTTLS with cert verification disabled${NC}"
echo "Command: LDAPTLS_REQCERT=never ldapwhoami -h $HOST -p $PLAIN_PORT -D \"$BINDDN\" -w $BINDPW -ZZ"
if $VERBOSE; then
    if ldapwhoami -vvv -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW" -ZZ; then
        echo -e "${GREEN}✓ STARTTLS test PASSED${NC}"
    else
        echo -e "${RED}✗ STARTTLS test FAILED${NC}"
    fi
else
    if ldapwhoami -h "$HOST" -p "$PLAIN_PORT" -D "$BINDDN" -w "$BINDPW" -ZZ 2>/dev/null; then
        echo -e "${GREEN}✓ STARTTLS test PASSED${NC}"
    else
        echo -e "${RED}✗ STARTTLS test FAILED${NC}"
    fi
fi
echo ""

# Test 3 retry: LDAPS with cert verification disabled
echo -e "${YELLOW}Test 3 (retry): LDAPS with cert verification disabled${NC}"
echo "Command: LDAPTLS_REQCERT=never ldapwhoami -H ldaps://$HOST:$LDAPS_PORT -D \"$BINDDN\" -w $BINDPW"
if $VERBOSE; then
    if ldapwhoami -vvv -H "ldaps://$HOST:$LDAPS_PORT" -D "$BINDDN" -w "$BINDPW"; then
        echo -e "${GREEN}✓ LDAPS test PASSED${NC}"
    else
        echo -e "${RED}✗ LDAPS test FAILED${NC}"
    fi
else
    if ldapwhoami -H "ldaps://$HOST:$LDAPS_PORT" -D "$BINDDN" -w "$BINDPW" 2>/dev/null; then
        echo -e "${GREEN}✓ LDAPS test PASSED${NC}"
    else
        echo -e "${RED}✗ LDAPS test FAILED${NC}"
    fi
fi
echo ""

echo "=========================================="
echo "All tests completed!"
echo "=========================================="
