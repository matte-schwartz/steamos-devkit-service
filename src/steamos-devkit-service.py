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
import avahi
import configparser
import dbus
import json
import os
import platform
import socketserver
import subprocess
import tempfile
import urllib.parse

SERVICE_PORT = 32000
PACKAGE = "steamos-devkit-service"
DEVKIT_HOOKS_DIR = "/usr/share/steamos-devkit/hooks"
CURRENT_TXTVERS = "txtvers=1"

entry_point = "devkit-1"
# root until config is loaded and told otherwise, etc.
entry_point_user = "root"
device_users = []
properties = {"txtvers": 1,
              "login": entry_point_user,
              "settings": "",
              "devkit1": [
                  entry_point
              ]}
machine_name = ''
hook_dirs = []
use_default_hooks = True

global_config = configparser.ConfigParser()
# Use str form to preserve case
global_config.optionxform = str
global_config.read(["/etc/steamos-devkit/steamos-devkit.conf", "/usr/share/steamos-devkit/steamos-devkit.conf"])

user_config_path = os.path.join(os.path.expanduser('~'), '.config', PACKAGE, PACKAGE + '.conf')
print("Trying to read user config from {}".format(user_config_path))

user_config = configparser.ConfigParser()
# Use str form to preserve case
user_config.optionxform = str
user_config.read(user_config_path)

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
            self.wfile.write(json.dumps(properties, indent=2).encode())
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
        global hook_dirs
        global use_default_hooks
        global device_users

        if (self.path == "/register"):
            from_ip = self.client_address[0]
            content_len = int(self.headers.get('Content-Length'))
            post_body = self.rfile.read(content_len)
            print("register request from {}".format(from_ip))
            filename = self.write_key(post_body)

            if not filename:
                self._send_headers(403, "text/plain")
                self.wfile.write("Failed to write ssh key")
                return

            # Run approve script
            approve_hook = find_hook(hook_dirs, use_default_hooks, "approve-ssh-key")
            if not approve_hook:
                self._send_headers(403, "text/plain")
                self.wfile.write("Failed to find approve hook");
                os.unlink(filename)
                return

            # Run hook and parse output
            p = subprocess.Popen([approve_hook, filename, from_ip], shell=False, stdout=subprocess.PIPE)
            output = ''
            for line in p.stdout:
                textline = line.decode(encoding='utf-8', errors="ignore")
                output += textline

            p.wait()
            output_object = json.loads(output)
            if ("error" in output_object):
                self._send_headers(403, "text/plain")
                self.wfile.write("approve-ssh-key:\n".encode())
                self.wfile.write(output_object["error"].encode())
                os.unlink(filename)
                return

            # Otherwise assume it passed
            install_hook = find_hook(hook_dirs, use_default_hooks, "install-ssh-key")
            if not install_hook:
                self._send_headers(403, "text-plain")
                self.wfile.write("Failed to find install-ssh-key hook")
                os.unlink(filename)
                return
            
            command = [install_hook, filename]
            # Append each user to command as separate arguments
            for u in device_users:
                command.append(u)

            p = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE)
            output = ''
            for line in p.stdout:
                textline = line.decode(encoding='utf-8', errors="ignore")
                output += textline
            p.wait()

            exit_code = p.returncode
            if (exit_code != 0):
                self._send_headers(500, "text/plain")
                self.wfile.write("install-ssh-key:\n".encode())
                self.wfile.write(output.encode())
                os.unlink(filename)
                return

            self._send_headers(200, "text/plain")
            self.wfile.write("Registered\n".encode())
            os.unlink(filename)

    def writefile(self, data):
        # Get 1 from the resulting tuple, since that's the filename
        filename = tempfile.mkstemp(prefix="devkit-", dir="/tmp/", text=True)[1]

        # Then open ourselves
        with open(filename, "w") as file:
            file.write(data.decode())
            file.close()

        return filename

    def write_key(self, post_body):
        # Write key to temp file and return filename if valid, etc.
        # Return None if invalid
        length = len(post_body)
        found_name = False
        filename = None

        if (length > 64 * 1024):
            print("Key length too long")
            return None
        if not post_body.decode().startswith('ssh-rsa'):
            print("Key doesn't start with ssh-rsa")
            return None

        # Get to the base64 bits
        index = 8
        while index < length and post_body[index] == ' ':
            index = index + 1

        # Make sure key is base64
        body_decoded = post_body.decode()
        while index < length:
            if ((body_decoded[index] == '+') or (body_decoded[index] == '/') or
               (body_decoded[index].isdigit()) or
               (body_decoded[index].isalpha())):
               index = index + 1
               continue
            elif (body_decoded[index] == '='):
                index = index + 1
                if ((index < length) and (body_decoded[index] == ' ')):
                    break
                elif ((index < length) and (body_decoded[index] == '=')):
                    index = index + 1
                    if ((index < length) and (body_decoded[index] == ' ')):
                        break
                print("Found = but no space or = next, invalid key")
                return None
            elif (body_decoded[index] == ' '):
                break
            else:
                print("Found invalid data, invalid key at index: {} data: {}".format(index, body_decoded[index]))
                return None

            index = index + 1

        print("Key is valid base64, writing to temp file index: {}".format(index))
        while (index < length):
            if (body_decoded[index] == ' '):
                # it's a space, the rest is name or magic phrase, don't write to disk
                if (found_name):
                    print("Found name ending at index {}".format(index))
                    length = index
                else:
                    print("Found name ending index {}".format(index))
                    found_name = True
            if (body_decoded[index] == '\0'):
                print("Found null terminator before expected")
                return None
            if (body_decoded[index] == '\n' and idx != length - 1):
                print("Found newline before expected")
                return None
            index = index + 1

        # write data to the file
        data = body_decoded[:length]
        filename = self.writefile(data.encode())

        print("Filename key written to: {}".format(filename))

        return filename

class DevkitService:
    def __init__(self):
        global entry_point_user
        global device_users
        global properties

        self.port = SERVICE_PORT
        # TODO: Change to sanitize_machine_name if needed
        self.name = machine_name
        self.host = ""
        self.domain = ""
        self.stype = "_steamos-devkit._tcp"
        self.text = ""

        if 'Settings' in global_config:
            settings = global_config["Settings"]
            self.settings = dict(settings.items())
            if 'Port' in settings:
                self.port = int(settings["Port"])

        if 'Settings' in user_config:
            settings = user_config["Settings"]
            self.settings = dict(settings.items())
            if 'Port' in settings:
                self.port = int(settings["Port"])

        properties["settings"] = json.dumps(self.settings)

        # Parse users from configs
        if os.geteuid() == 0:
            # Running as root, maybe warn?
            print("Running as root, Probably shouldn't be\n")
            if 'Users' in global_config:
                users = global_config["Users"]
                if 'ShellUsers' in users:
                    device_users = users["ShellUsers"]
        else:
            if 'Users' in user_config:
                users = user_config["Users"]
                if 'ShellUsers' in users:
                    device_users = users["ShellUsers"]
            else:
                device_users = [os.getlogin()]

        # If only one user, that's the entry point user
        # Otherwise entry_point_user needs to be root to be able to switch between users
        if len(device_users) == 1:
            entry_point_user = device_users[0]
            properties["login"] = entry_point_user

        self.httpd = socketserver.TCPServer(("", self.port), DevkitHandler, bind_and_activate=False)
        print("serving at port: {}".format(self.port))
        print("machine name: {}".format(machine_name))
        self.httpd.allow_reuse_address = True
        self.httpd.server_bind()
        self.httpd.server_activate()

    def publish(self):
        global entry_point
        global entry_point_user

        bus = dbus.SystemBus()
        self.text = ["{}".format(CURRENT_TXTVERS).encode(),
                     "settings={}".format(json.dumps(self.settings)).encode(),
                     "login={}".format(entry_point_user).encode(),
                     "devkit1={}".format(entry_point).encode()
                    ]
        server = dbus.Interface(
            bus.get_object(
                avahi.DBUS_NAME,
                avahi.DBUS_PATH_SERVER),
            avahi.DBUS_INTERFACE_SERVER)

        g = dbus.Interface(
            bus.get_object(avahi.DBUS_NAME,
                server.EntryGroupNew()),
            avahi.DBUS_INTERFACE_ENTRY_GROUP)
        g.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0),
                     self.name, self.stype, self.domain, self.host,
                     dbus.UInt16(int(self.port)), self.text)

        g.Commit()
        self.group = g
        

    def unpublish(self):
        self.group.Reset()

    def runServer(self):
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass

        self.httpd.server_close()
        print("done serving at port: {}".format(self.port))

if __name__ == "__main__":
    service = DevkitService()

    service.publish()
    service.runServer()

    service.unpublish()

