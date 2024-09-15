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

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from ldaptor.protocols.ldap import ldapserver, ldaperrors
from twisted.internet import protocol, reactor
from twisted.python import log
from functools import partial
import sys
import requests
import os

from mock import Mock

class OidcProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log requests and responses.
    """

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Log the representation of the request received.
        """
        print(repr(request))
        if isinstance(request, pureldap.LDAPBindRequest):
            # Get OIDC token throught password grant
            ## Quick and dirty username from DN assuming it is CN
            username = request.dn.split(b',')[0][3:]
            password = request.auth

            ## TODO : Nice to have Add support for OTP within password

            url = os.environ.get("LDAP_PROXY_TOKEN_URL")
            client_id = os.environ.get("LDAP_PROXY_CLIENT_ID")
            client_secret = os.environ.get("LDAP_PROXY_CLIENT_SECRET")

            payload = 'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={username}&password={password}'.format(client_id=client_id, client_secret=client_secret, username=username.decode('utf-8'), password=password.decode('utf-8'))
            headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }
            print(url)
            oidc_response = requests.request("POST", url, headers=headers, data=payload)

            # Logging username and status code
            print(username.decode('utf-8') + " " + str(oidc_response.status_code))
            
            if oidc_response.status_code == requests.codes['ok']:
                # LDAP Bind success
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode
                    )
            else:
                # Invalid credentials (see keycloak logs)
                msg= pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
            reply(msg)
        if isinstance(request, pureldap.LDAPSearchRequest):
            # TODO: If needed, for confidential clients with service account only, search within keycloak API and reply with search result, dummy response for now.
            msg = pureldap.LDAPSearchResultDone(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        if isinstance(request, pureldap.LDAPExtendedRequest):
            msg = pureldap.LDAPExtendedResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        if isinstance(request, pureldap.LDAPUnbindRequest):
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.Success.resultCode
            )
            reply(msg)
        return None

    ## TODO: This is a Workaround, implement a cleaner proxy class from class ServerBase
    def connectionMade(self):
        """ Overridden method to prevent proxy from trying to connect non-existing backend server.
        Mocking client class to drop every operation made to it"""
        print("connectionMade called")
        self.client = Mock()
        ldapserver.BaseLDAPServer.connectionMade(self)
    
if __name__ == '__main__':
    """
    Demonstration LDAP OIDC proxy; listens on localhost:389 and translate to OIDC protocol
    """
    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'NoEndpointneeded'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = OidcProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(389, factory)
    reactor.run()