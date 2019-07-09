# Databricks CLI
# Copyright 2017 Databricks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"), except
# that the use of services to which certain application programming
# interfaces (each, an "API") connect requires that the user first obtain
# a license for the use of the APIs from Databricks, Inc. ("Databricks"),
# by creating an account at www.databricks.com and agreeing to either (a)
# the Community Edition Terms of Service, (b) the Databricks Terms of
# Service, or (c) another written agreement between Licensee and Databricks
# for the use of the APIs.
#
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid
import json
import socket
import requests
import webbrowser as wb

try:
    from BaseHTTPServer import BaseHTTPRequestHandler
except ImportError:
    from http.server import BaseHTTPRequestHandler

try:
    from SocketServer import TCPServer as HTTPServer
except ImportError:
    from http.server import HTTPServer

try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

# Success page returned to the user
SUCCESS_HTML = b"""<html>
  <head>
    <title>Get AAD Token: Success</title>
  </head>
  <body>
    <br/>
    <span style="color:green">Success!</span>
     New AAD Token request has been completed successfully.
  </body>
</html>
"""

# Failure page returned to the user
FAILURE_HTML = b"""<html>
  <head>
    <title>Get AAD Token: Failed</title>
  </head>
  <body>
    <br/>
    <span style="color:red">Failed!</span>
     Failed to generate a new AAD Token.
  </body>
</html>
"""

class LocalHTTPServer(HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.socket.bind(self.server_address)

class AADTokenRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, resource_id, client_id, client_secret, out_file, *args):
        self.out_file = out_file
        self.client_id = client_id
        self.resource_id = resource_id
        self.client_secret = client_secret
        BaseHTTPRequestHandler.__init__(self, *args)

    def send_reply(self, code, text):
        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(text)

    # Handle POST Requests
    def do_POST(self):
        response = self.rfile.read(int(self.headers.getheader('Content-Length')))
        id_token = parse_qs(response)['id_token']
        payload = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': id_token,
            'client_id': self.client_id,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_secret': self.client_secret,
            'resource': self.resource_id,
            'requested_token_use': 'on_behalf_of',
            'scope': 'user_impersonation'
        }
        r = requests.post(
            'https://login.microsoftonline.com/common/oauth2/token',
            data = payload
        )
        if r.status_code == 200:
            handle_response(json.loads(r.text), self.out_file)
            self.send_reply(200, SUCCESS_HTML)
        else:
            print('Error occured while generating the AAD token.')
            self.send_reply(400, FAILURE_HTML)

def get_server(resource_id, client_id, client_secret, callback_port, out_file):
    """Create a handler and instatiate a server with it"""
    def gen_handler(*args):
        AADTokenRequestHandler(resource_id, client_id, client_secret,
                               out_file, *args)
    return LocalHTTPServer(("localhost", callback_port), gen_handler)

def run_local_server(server):
    server.handle_request()

def handle_response(json_response, out_file):
    if json_response['access_token'] and json_response['refresh_token']:
        output = '\n'.join([
            '********** Start AAD OBO Access Token ***********',
            json_response['access_token'],
            '*********** End AAD OBO Access Token ************',
            '********** Start AAD OBO Refresh Token **********',
            json_response['refresh_token'],
            '*********** End AAD OBO Refresh Token ***********'
        ])
        # Write to the given file (if present)
        if out_file:
            of = open(out_file, "w+")
            of.write(output)
            of.close()
            print("AAD token successfully written to file: " + out_file)
        else:
            print(output)
    else:
        print('No AAD token returned. API Response: ' + json_response)

class TokensApi(object):
    def generate_new_aad_token(self, resource_id, client_id, client_secret,
                               callback_port, out_file):
        server = get_server(resource_id, client_id, client_secret,
                            callback_port, out_file)
        wb.open_new_tab(
            'https://login.microsoftonline.com/common/oauth2/authorize?' +
            'client_id=' + client_id +
            '&nonce=' + str(uuid.uuid4()) +
            '&response_type=id_token+code' +
            '&scope=https%3A%2F%2Fmanagement.azure.com%2Fuser_impersonation' +
            '&response_mode=form_post'
        )
        run_local_server(server)

    def refresh_aad_token(self, resource_id, client_id, client_secret,
                          refresh_token, out_file):
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': client_id,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_secret': client_secret,
            'resource': resource_id
        }
        r = requests.post(
            'https://login.microsoftonline.com/common/oauth2/token',
            data = payload
        )
        if r.status_code == 200:
            handle_response(json.loads(r.text), out_file)
        else:
            print('Error occured while refreshing the given AAD token.')
