#!/usr/bin/python
#
# Copyright 2016 Canonical Ltd
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

import os
import glob
import subprocess
import shlex
from charmhelpers.core.hookenv import(
    log,
)


def format_pci_addr(pci_addr):
    domain, bus, slot_func = pci_addr.split(':')
    slot, func = slot_func.split('.')
    return '{}:{}:{}.{}'.format(domain.zfill(4), bus.zfill(2), slot.zfill(2),
                                func)


class PCINetDevice(object):

    def __init__(self, pci_address):
        self.pci_address = pci_address
        self.interface_name = None
        self.mac_address = None
        self.state = None
        self.update_attributes()

    def update_attributes(self):
        self.update_interface_info()

    def update_interface_info(self):
        self.update_interface_info_eth()

    def update_interface_info_eth(self):
        net_devices = self.get_sysnet_interfaces_and_macs()
        for interface in net_devices:
            if self.pci_address == interface['pci_address']:
                self.interface_name = interface['interface']
                self.mac_address = interface['mac_address']
                self.state = interface['state']

    def get_sysnet_interfaces_and_macs(self):
        net_devs = []
        for sdir in glob.glob('/sys/class/net/*'):
            sym_link = sdir + "/device"
            if os.path.islink(sym_link):
                fq_path = os.path.realpath(sym_link)
                path = fq_path.split('/')
                if 'virtio' in path[-1]:
                    pci_address = path[-2]
                else:
                    pci_address = path[-1]
                net_devs.append({
                    'interface': self.get_sysnet_interface(sdir),
                    'mac_address': self.get_sysnet_mac(sdir),
                    'pci_address': pci_address,
                    'state': self.get_sysnet_device_state(sdir),
                })
        return net_devs

    def get_sysnet_mac(self, sysdir):
        mac_addr_file = sysdir + '/address'
        with open(mac_addr_file, 'r') as f:
            read_data = f.read()
        mac = read_data.strip()
        log('mac from {} is {}'.format(mac_addr_file, mac))
        return mac

    def get_sysnet_device_state(self, sysdir):
        state_file = sysdir + '/operstate'
        with open(state_file, 'r') as f:
            read_data = f.read()
        state = read_data.strip()
        log('state from {} is {}'.format(state_file, state))
        return state

    def get_sysnet_interface(self, sysdir):
        return sysdir.split('/')[-1]


class PCINetDevices(object):

    def __init__(self):
        pci_addresses = self.get_pci_ethernet_addresses()
        self.pci_devices = [PCINetDevice(dev) for dev in pci_addresses]

    def get_pci_ethernet_addresses(self):
        cmd = ['lspci', '-m', '-D']
        lspci_output = subprocess.check_output(cmd)
        pci_addresses = []
        for line in lspci_output.split('\n'):
            columns = shlex.split(line)
            if len(columns) > 1 and columns[1] == 'Ethernet controller':
                pci_address = columns[0]
                pci_addresses.append(format_pci_addr(pci_address))
        return pci_addresses

    def update_devices(self):
        for pcidev in self.pci_devices:
            pcidev.update_attributes()

    def get_macs(self):
        macs = []
        for pcidev in self.pci_devices:
            if pcidev.mac_address:
                macs.append(pcidev.mac_address)
        return macs

    def get_device_from_mac(self, mac):
        for pcidev in self.pci_devices:
            if pcidev.mac_address == mac:
                return pcidev
        return None

    def get_device_from_pci_address(self, pci_addr):
        for pcidev in self.pci_devices:
            if pcidev.pci_address == pci_addr:
                return pcidev
        return None
