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

import sys

from twisted.internet import defer
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.task import react
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry


@defer.inlineCallbacks
def onConnect(client):
    # The following arguments may be also specified as unicode strings
    # but it is recommended to use byte strings for ldaptor objects
    basedn = b"dc=example,dc=org"
    # Cn & pw replaced with keycloak test user
    binddn = b"cn=test,ou=people,dc=example,dc=org"
    bindpw = b"pwtest" 
    try:
        yield client.bind(binddn, bindpw)
    except Exception as ex:
        print(repr(ex))
        raise
    o = LDAPEntry(client, basedn)
    
    print(repr(o));
    print(o.getLDIF());
    print("Done");
    #results = yield o.search(filterText=query)
    #for entry in results:
    #    print(entry.getLDIF())


def onError(err):
    err.printDetailedTraceback(file=sys.stderr)


def main(reactor):
    endpoint_str = "tcp:host=127.0.0.1:port=389"
    e = clientFromString(reactor, endpoint_str)
    d = connectProtocol(e, LDAPClient())
    d.addCallback(onConnect)
    d.addErrback(onError)
    return d


react(main)