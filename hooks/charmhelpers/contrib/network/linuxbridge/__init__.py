# Copyright 2014-2015 Canonical Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

''' Helpers for interacting with LinuxBridge '''
import subprocess
import os
from charmhelpers.core.hookenv import (
    log, WARNING
)
from charmhelpers.core.host import (
    service
)


def add_lxbridge(name, datapath_type=None):
    ''' Add the named bridge to linuxbridge '''
    log('Creating bridge {}'.format(name))
    cmd = ["brctl", "--", "addbr", name]
    if datapath_type is not None:
        cmd += ['--', 'set', 'bridge', name,
                'datapath_type={}'.format(datapath_type)]
    subprocess.call(cmd)


def del_lxbridge(name):
    ''' Delete the named bridge from linuxbridge '''
    log('Deleting bridge {}'.format(name))
    subprocess.check_call(["brctl", "--", "delbr", name])


def add_lxbridge_port(name, port, promisc=False):
    ''' Add a port to the named linuxbridge bridge '''
    log('Adding port {} to bridge {}'.format(port, name))
    subprocess.call(["brctl", "--", "addif",
                           name, port])
    subprocess.check_call(["ip", "link", "set", port, "up"])
    if promisc:
        subprocess.check_call(["ip", "link", "set", port, "promisc", "on"])
    else:
        subprocess.check_call(["ip", "link", "set", port, "promisc", "off"])


def del_lxbridge_port(name, port):
    ''' Delete a port from the named linuxbridge bridge '''
    log('Deleting port {} from bridge {}'.format(port, name))
    subprocess.check_call(["ovs-vsctl", "--", "delif",
                           name, port])
    subprocess.check_call(["ip", "link", "set", port, "down"])
    subprocess.check_call(["ip", "link", "set", port, "promisc", "off"])
