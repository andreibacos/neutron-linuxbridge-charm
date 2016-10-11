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

import glob
import os
import uuid
from pci import PCINetDevices
from charmhelpers.core.hookenv import (
    config,
    relation_get,
    relation_ids,
    related_units,
    unit_get,
    network_get_primary_address,
    log,
    INFO,
    ERROR,
)
from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_os_codename_install_source,
    git_clone_and_install,
    git_default_repos,
    git_generate_systemd_init_files,
    git_install_requested,
    git_pip_venv_dir,
    git_src_dir,
    get_hostname,
    make_assess_status_func,
    os_release,
    pause_unit,
    resume_unit,
    get_host_ip,
)
from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.openstack.utils import get_host_ip
from charmhelpers.contrib.network.ip import get_address_in_network
from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    NeutronAPIContext,
)
from charmhelpers.contrib.openstack.neutron import (
    neutron_plugin_attribute,
    parse_data_port_mappings,
)
from charmhelpers.core.unitdata import kv


class LBPluginContext(context.NeutronContext):
    interfaces = []

    @property
    def plugin(self):
        return 'lb'

    @property
    def network_manager(self):
        return 'neutron'

    @property
    def neutron_security_groups(self):
        if config('disable-security-groups'):
            return False
        neutron_api_settings = NeutronAPIContext()()
        return neutron_api_settings['neutron_security_groups']

    def lb_ctxt(self):
        # In addition to generating config context, ensure the OVS service
        # is running and the OVS bridge exists. Also need to ensure
        # local_ip points to actual IP, not hostname.
        lb_ctxt = super(LBPluginContext, self).lb_ctxt()
        if not lb_ctxt:
            return {}

        conf = config()

        fallback = get_host_ip(unit_get('private-address'))
        if config('os-data-network'):
            # NOTE: prefer any existing use of config based networking
            lb_ctxt['local_ip'] = \
                get_address_in_network(config('os-data-network'),
                                       fallback)
        else:
            # NOTE: test out network-spaces support, then fallback
            try:
                lb_ctxt['local_ip'] = get_host_ip(
                    network_get_primary_address('data')
                )
            except NotImplementedError:
                lb_ctxt['local_ip'] = fallback

        neutron_api_settings = NeutronAPIContext()()

        portmaps = context.DataPortContext()()
        if not portmaps:
            log("There are no data-ports defined for this host.", level=ERROR)
        lb_ctxt['interface_mappings'] = "physnet1:%s" % portmaps.keys()[0] 
        #lb_ctxt['interface_mappings'] = conf['interface-mappings']
        lb_ctxt['neutron_security_groups'] = self.neutron_security_groups
        lb_ctxt['l2_population'] = neutron_api_settings['l2_population']
        lb_ctxt['overlay_network_type'] = \
            neutron_api_settings['overlay_network_type']
        # TODO: We need to sort out the syslog and debug/verbose options as a
        # general context helper
        lb_ctxt['use_syslog'] = conf['use-syslog']
        lb_ctxt['verbose'] = conf['verbose']
        lb_ctxt['debug'] = conf['debug']
        lb_ctxt['prevent_arp_spoofing'] = conf['prevent-arp-spoofing']
        lb_ctxt['enable_vxlan'] = conf['enable-vxlan']
        lb_ctxt['enable_dpdk'] = conf['enable-dpdk']

        net_dev_mtu = neutron_api_settings.get('network_device_mtu')
        if net_dev_mtu:
            # neutron.conf
            lb_ctxt['network_device_mtu'] = net_dev_mtu
            # ml2 conf
            lb_ctxt['veth_mtu'] = net_dev_mtu

        mappings = config('bridge-mappings')
        if mappings:
            lb_ctxt['bridge_mappings'] = ','.join(mappings.split())

        flat_providers = config('flat-network-providers')
        if flat_providers:
            lb_ctxt['network_providers'] = ','.join(flat_providers.split())

        vlan_ranges = config('vlan-ranges')
        if vlan_ranges:
            lb_ctxt['vlan_ranges'] = ','.join(vlan_ranges.split())

        return lb_ctxt


class L3AgentContext(OSContextGenerator):

    def __call__(self):
        neutron_api_settings = NeutronAPIContext()()
        ctxt = {}
        if neutron_api_settings['enable_dvr']:
            ctxt['agent_mode'] = 'dvr'
            if not config('ext-port'):
                ctxt['external_configuration_new'] = True
        else:
            ctxt['agent_mode'] = 'legacy'

        return ctxt


def resolve_dpdk_ports():
    '''
    Resolve local PCI devices from configured mac addresses
    using the data-port configuration option

    @return: OrderDict indexed by PCI device address.
    '''
    ports = config('data-port')
    devices = PCINetDevices()
    resolved_devices = {}
    db = kv()
    if ports:
        # NOTE: ordered dict of format {[mac]: bridge}
        portmap = parse_data_port_mappings(ports)
        for mac, bridge in portmap.iteritems():
            pcidev = devices.get_device_from_mac(mac)
            if pcidev:
                # NOTE: store mac->pci allocation as post binding
                #       to dpdk, it disappears from PCIDevices.
                db.set(mac, pcidev.pci_address)
                db.flush()

            pci_address = db.get(mac)
            if pci_address:
                resolved_devices[pci_address] = bridge

    return resolved_devices


def parse_cpu_list(cpulist):
    '''
    Parses a linux cpulist for a numa node

    @return list of cores
    '''
    cores = []
    ranges = cpulist.split(',')
    for cpu_range in ranges:
        cpu_min_max = cpu_range.split('-')
        cores += range(int(cpu_min_max[0]),
                       int(cpu_min_max[1]) + 1)
    return cores


def numa_node_cores():
    '''Dict of numa node -> cpu core mapping'''
    nodes = {}
    node_regex = '/sys/devices/system/node/node*'
    for node in glob.glob(node_regex):
        index = node.lstrip('/sys/devices/system/node/node')
        with open(os.path.join(node, 'cpulist')) as cpulist:
            nodes[index] = parse_cpu_list(cpulist.read().strip())
    return nodes


class DPDKDeviceContext(OSContextGenerator):

    def __call__(self):
        return {'devices': resolve_dpdk_ports(),
                'driver': config('dpdk-driver')}


class OVSDPDKDeviceContext(OSContextGenerator):

    def cpu_mask(self):
        '''
        Hex formatted CPU mask based on using the first
        config:dpdk-socket-cores cores of each NUMA node
        in the unit.
        '''
        num_cores = config('dpdk-socket-cores')
        mask = 0
        for cores in numa_node_cores().itervalues():
            for core in cores[:num_cores]:
                mask = mask | 1 << core
        return format(mask, '#04x')

    def socket_memory(self):
        '''
        Formatted list of socket memory configuration for dpdk using
        config:dpdk-socket-memory per NUMA node.
        '''
        sm_size = config('dpdk-socket-memory')
        node_regex = '/sys/devices/system/node/node*'
        mem_list = [str(sm_size) for _ in glob.glob(node_regex)]
        if mem_list:
            return ','.join(mem_list)
        else:
            return str(sm_size)

    def device_whitelist(self):
        '''Formatted list of devices to whitelist for dpdk'''
        _flag = '-w {device}'
        whitelist = []
        for device in resolve_dpdk_ports():
            whitelist.append(_flag.format(device=device))
        return ' '.join(whitelist)

    def __call__(self):
        ctxt = {}
        whitelist = self.device_whitelist()
        if whitelist:
            ctxt['dpdk_enabled'] = config('enable-dpdk')
            ctxt['device_whitelist'] = self.device_whitelist()
            ctxt['socket_memory'] = self.socket_memory()
            ctxt['cpu_mask'] = self.cpu_mask()
        return ctxt


SHARED_SECRET = "/etc/neutron/secret.txt"


def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret


class SharedSecretContext(OSContextGenerator):

    def __call__(self):
        if NeutronAPIContext()()['enable_dvr'] or \
                config('enable-local-dhcp-and-metadata'):
            ctxt = {
                'shared_secret': get_shared_secret(),
            }
        else:
            ctxt = {}
        return ctxt


class RemoteRestartContext(OSContextGenerator):

    def __call__(self):
        for rid in relation_ids('neutron-plugin'):
            for unit in related_units(rid):
                restart_uuid = relation_get(
                    attribute='restart-trigger',
                    rid=rid,
                    unit=unit)
                if restart_uuid:
                    return {'restart_trigger': restart_uuid}
        return {}


class APIIdentityServiceContext(context.IdentityServiceContext):

    def __init__(self):
        super(APIIdentityServiceContext,
              self).__init__(rel_name='neutron-plugin-api')

    def __call__(self):
        ctxt = super(APIIdentityServiceContext, self).__call__()
        if not ctxt:
            return
        for rid in relation_ids('neutron-plugin-api'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt['region'] = rdata.get('region')
                if ctxt['region']:
                    return ctxt
        return ctxt
