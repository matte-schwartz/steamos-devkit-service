#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#MIT License
#
#Copyright (c) 2022 Valve Software inc., Collabora Ltd
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

from http.server import BaseHTTPRequestHandler
import configparser
import json
import os
import platform
import socketserver
import subprocess
import urllib.parse

SERVICE_PORT = 32000
PACKAGE = "steamos-devkit-service"
DEVKIT_HOOKS_DIR = "/usr/share/steamos-devkit/hooks"

# root until config is loaded and told otherwise, etc.
entry_point_user = "root"
properties = {}
machine_name = ''
hook_dirs = []
use_default_hooks = True

global_config = configparser.ConfigParser()
global_config.read(["/etc/steamos-devkit/steamos-devkit.conf", "/usr/share/steamos-devkit/steamos-devkit.conf"])

def find_hook(hook_dirs, use_default_hooks, name):
    # First see if it exists in the given paths.
    for path in hook_dirs:
        test_path = os.path.join(path, name)
        if (os.path.exists(test_path) and os.access(test_path, os.X_OK)):
            return test_path
    
    if (not use_default_hooks):
        print("Error: Unable to find hook for {} in hook directories\n".format(name))
        return None

    test_path = "/etc/{}/hooks/{}".format(PACKAGE, name)
    if (os.path.exists(test_path) and os.access(test_path, os.X_OK)):
        return test_path

    test_path = "{}/{}".format(DEVKIT_HOOKS_DIR, name)
    if (os.path.exists(test_path) and os.access(test_path, os.X_OK)):
        return test_path

    test_path = "{}/{}.sample".format(DEVKIT_HOOKS_DIR, name)
    if (os.path.exists(test_path) and os.access(test_path, os.X_OK)):
        return test_path

    test_path = "{}/../hooks/{}".format(os.path.dirname(os.path.realpath(__file__)), name)
    if (os.path.exists(test_path) and os.access(test_path, os.X_OK)):
        return test_path

    print("Error:: Unable to find hook for {} in /etc/{}/hooks or {}".format(name, PACKAGE, DEVKIT_HOOKS_DIR))
    return None

# Run devkit-1-identify hook to get hostname, otherwise use default platform.node()
identify_hook = find_hook(hook_dirs, use_default_hooks, "devkit-1-identify")
if (identify_hook):
    # Run hook and parse machine_name out
    p = subprocess.Popen(identify_hook, shell=False, stdout=subprocess.PIPE)
    output = ''
    for line in p.stdout:
        textline = line.decode(encoding='utf-8', errors="ignore")
        output += textline
    p.wait()
    output_object = json.loads(output)
    if ('machine_name' in output_object):
        machine_name = output_object["machine_name"]

if not machine_name:
    machine_name = platform.node()

class DevkitHandler(BaseHTTPRequestHandler):
    def _send_headers(self, code, type):
        self.send_response(code)
        self.send_header("Content-type", type)
        self.end_headers()

    def do_GET(self):
        print("GET request to path {} from {}".format(self.path, self.client_address[0]))

        if (self.path == "/login-name"):
            self._send_headers(200, "text/plain")
            self.wfile.write(entry_point_user.encode())
            return

        elif (self.path == "/properties.json"):
            self._send_headers(200, "application/json")
            self.wfile.write(json.dumps(properties).encode())
            return
        
        else:
            query = urllib.parse.parse_qs(self.path[2:])
            print("query is {}".format(query))

            if (len(query) > 0 and query["command"]):
                command = query["command"][0]
    
                if (command == "ping"):
                    self._send_headers(200, "text/plain")
                    self.wfile.write("pong\n".encode())
                    return
                else:
                    self._send_headers(404, "")
                    return

        self._send_headers(200, "text/html")
        self.wfile.write("Get works\n".encode())

    def do_POST(self):
        if (self.path == "/register"):
            print("register request from {}".format(self.client_address[0]))
            self._send_headers(200)
            self.wfile.write("Registered\n".encode())


class DevkitService:
    def __init__(self):
        # TODO: Get from config if set
        self.port = SERVICE_PORT

        self.httpd = socketserver.TCPServer(("", self.port), DevkitHandler, bind_and_activate=False)
        print("serving at port: {}".format(self.port))
        print("machine name: {}".format(machine_name))
        self.httpd.allow_reuse_address = True
        self.httpd.server_bind()
        self.httpd.server_activate()

        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass

        self.httpd.server_close()
        print("done serving at port: {}".format(self.port))

if __name__ == "__main__":
    service = DevkitService()

