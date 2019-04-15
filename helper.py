#! /usr/bin/env python
import subprocess

from fabric.api import *
from fabric.operations import run


# Helper utility to perform certain independent tasks

def get_server_public_ssh_key(server_ip):
    """Method to craete ssh key-pair in the remote server 
       and return public ssh key
    """
    with settings(host_string=server_ip,
                  user='root',
                  port=22,
                  password='Ubuntu123',
                  warn_only=True), hide('output', 'running'):
        cmd_to_execute = 'ssh-keygen -t rsa -f .ssh/id_rsa -q -P ""; cat .ssh/id_rsa.pub'
        cmd_out = run(cmd_to_execute, timeout=360)
        return cmd_out


def get_local_pub_ssh_key():
    """Method to craete ssh key-pair locally and return public ssh key
    """
    system_ssh_key = subprocess.check_output("cat ~/.ssh/id_rsa.pub",
                                             shell=True)
    if not system_ssh_key:
        cmd_to_execute = 'ssh-keygen -t rsa -f .ssh/id_rsa -q -P ""; cat .ssh/id_rsa.pub'
        system_ssh_key = subprocess.check_output(cmd_to_execute, shell=True)
    return str(system_ssh_key).strip()


def get_lan_dict_list():
    """Compose the LAN object
    """
    lan1 = {'name': 'public-lan',
            'public': True}
    lan2 = {'name': 'private-lan',
            'public': False}
    the_lans = [lan1, lan2]
    return the_lans


def get_volume_dict_list(name, image_id, ssh_keys):
    """Compose the Volume object
    """
    volume = {
        'name': name,
        'size': 10,
        'availability_zone': 'AUTO',
        'image': image_id,
        'image_password': 'Ubuntu123',
        'disk_type': 'HDD',
        'bus': 'VIRTIO',
        'ssh_keys': ssh_keys
    }
    the_volumes_l = [volume]
    return the_volumes_l


def get_ssh_firewall_dict_list():
    """Compose a ssh firewall rule
    """
    fwrule1 = {
        'name': 'Allow SSH',
        'protocol': 'TCP',
        'source_ip': '0.0.0.0',
        'port_range_start': 22,
        'port_range_end': 22
    }
    firewall_l = [fwrule1]
    return firewall_l


def get_nic_dict_list(firewall_l, public_lan_id=None,
                      private_lan_id=None):
    """Compose Nic Objects as per LAN networks
    """
    the_nics_l = list()
    if public_lan_id:
        nic1 = {
            'name': 'nic1',
            'dhcp': 'true',
            'lan': public_lan_id,
            'firewall_active': True,
            'firewall_rules': firewall_l
        }
        the_nics_l.append(nic1)
    if private_lan_id:
        nic2 = {
            'name': 'nic2',
            'dhcp': 'true',
            'lan': private_lan_id,
            'firewall_active': True,
            'firewall_rules': firewall_l
        }
        the_nics_l.append(nic2)
    return the_nics_l


def get_server_dict(name, volumes_l, nics_l):
    """Compose Server Objects as per name, volumes and nic
    """
    serv1 = {
        'name': name,
        'ram': 2048,
        'cores': 1,
        'create_volumes': volumes_l,
        'nics': nics_l
    }
    return serv1
