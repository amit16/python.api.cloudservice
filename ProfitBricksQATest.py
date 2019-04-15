#! /usr/bin/env python
"""
Created on Aug 8, 2018

@author: amitkumar

QA Task :
    Test should be able to check that its possible to do the following using API:
    1. Create the below mentioned Data Center.
    Note: Please use an sshKey when creating the storages.
    2. Check whether the Frontend Server is up and running.
    3. Change the Data Center by increasing the Cores/RAM being used.
    4. Create a file on the Frontend Server and transfer it to the Backend Server.
    The Data Center to create should consist of:
        - At least two Serves (e.g. Frontend and Backend)
        - All Servers are connected per private LAN
        - Only one Server (e.g. Frontend) is connected to a public LAN
"""

import unittest

import yaml

from helper import *
from profitbricksapi_lib import *

LOGGER = logging.getLogger(__name__)


class ProfitBricksQATest(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        logging.basicConfig(level=logging.DEBUG)
        try:
            LOGGER.info("Starting ProfitBricksQA Task ...")
            user_config_yaml = open("user_config.yaml")
            user_input_d = yaml.load(user_config_yaml)

            username = user_input_d['account_info'].get('username')
            password = user_input_d['account_info'].get('password')
            self.datacenter_name = user_input_d['datacenter'].get('name')
            self.datacenter_desc = user_input_d['datacenter'].get(
                'description')
            self.datacenter_location = user_input_d['datacenter'].get(
                'location')

            self.cloud_api = ProfitBricksApiLib(username=username,
                                                password=password)
        except Exception as e:
            msg = 'ProfitBricksQATest: %s error' % (e)
            LOGGER.error(msg)
            raise

    def test_datacenter_create(self):
        """Creates a Datacenter with two lan networks - one public
           and one private, then verify the operation is 
           successfull.
        """
        try:
            # Craete LAN Network Objects
            the_lans = get_lan_dict_list()

            LOGGER.info("Creating Datacenter : {0} with a public and" +
                        " private network ...".
                        format(self.datacenter_name))
            LOGGER.debug("LAN Networks : {}".format(the_lans))

            dc_o = {'name': self.datacenter_name,
                    'description': self.datacenter_desc,
                    'location': self.datacenter_location,
                    'lans': the_lans
                    }
            dc_create_response = self.cloud_api.create_datacenter(
                datacenter=dc_o)
            self.cloud_api.poll_till_completion(dc_create_response)
            if not dc_create_response:
                LOGGER.error("Datacenter Creation Test FAILED !")
                return False

            LOGGER.info("Datacenter Creation Test PASSED !")
            return True
        except Exception as e:
            msg = 'test_datacenter_create: %s error' % (e)
            LOGGER.error(msg)
            raise

    def test_server_create(self):
        """Creates two servers - FrontEnd and BackEnd in the 
           given Datacenter and verifies the operation is successfull
        """
        try:
            LOGGER.info(
                "Starting Test to Create FrontEnd and BackEnd Servers ...")
            # Get Datacenter ID
            datacenter_id = self.__get_datacenter_id(self.datacenter_name)
            if not datacenter_id:
                return False

            # Get public and private LAN Ids
            lan_response = self.cloud_api.list_lans(
                datacenter_id=datacenter_id)
            lans_l = lan_response['items']
            for lan in lans_l:
                if lan['properties']['public']:
                    public_lan_id = lan['id']
                else:
                    private_lan_id = lan['id']

            # Get Debian Server Image ID
            image_list = self.cloud_api.list_images()
            for image in image_list['items']:
                if self.datacenter_location in image['properties']['location']:
                    if 'Debian-testing-server' in image['properties']['name']:
                        image_id = image['id']

            # SSH Firewall Rule
            firewall_l = get_ssh_firewall_dict_list()

            # Get the local public ssh key for creating FrontEnd Volume
            LOGGER.info("Getting the local public key from ~/.ssh/")
            local_ssh_key = get_local_pub_ssh_key()

            # Building Volume and Nic Objects for FrontEnd Server
            the_volumes_l = get_volume_dict_list(
                name='FrontEndVolume', image_id=image_id,
                ssh_keys=[str(local_ssh_key)])
            nics_l = get_nic_dict_list(
                firewall_l=firewall_l, public_lan_id=public_lan_id,
                private_lan_id=private_lan_id)

            frontend_server = get_server_dict(
                name='FrontEnd', volumes_l=the_volumes_l,
                nics_l=nics_l)
            LOGGER.info("Creating FrontEnd Server ...")
            LOGGER.debug("Volume : {0}, Nic : {1}, Server : {2}". \
                         format(the_volumes_l, nics_l, frontend_server))

            # Create FrontEnd Server
            response_serv1 = self.cloud_api.create_server(
                datacenter_id=datacenter_id,
                server=frontend_server)
            self.cloud_api.poll_till_completion(response_serv1)
            if not response_serv1['id']:
                LOGGER.error("FrontEnd Server Creation Failed")
                return False

            # Get FrontEnd Server Public IP
            public_ip_serv1 = self.__get_ip(
                datacenter_id=datacenter_id,
                server_id=response_serv1['id'],
                nic_name='nic1')
            LOGGER.info('Frontend Public IP: {}'.format(public_ip_serv1))

            # Get FrontEnd Server Public SSH key to create BackEnd Server 
            serv1_ssh_key = get_server_public_ssh_key(public_ip_serv1)
            LOGGER.info('Frontend Public SSH key: {}'.format(serv1_ssh_key))

            # Building Volume and Nic Objects for BackEnd Server
            the_volumes_l = get_volume_dict_list(
                name='BackEndVolume', image_id=image_id,
                ssh_keys=[str(serv1_ssh_key)])
            nics_l = get_nic_dict_list(
                firewall_l=firewall_l,
                private_lan_id=private_lan_id)

            backend_server = get_server_dict(
                name='BackEnd', volumes_l=the_volumes_l,
                nics_l=nics_l)
            LOGGER.info("Creating BackEnd Server ...")
            LOGGER.debug("Volume : {0}, Nic : {1}, Server : {2}". \
                         format(the_volumes_l, nics_l, backend_server))

            # Create BackEnd Server
            response_serv2 = self.cloud_api.create_server(
                datacenter_id=datacenter_id,
                server=backend_server)
            self.cloud_api.poll_till_completion(response_serv2)
            if not response_serv2['id']:
                LOGGER.error("BackEnd Server Creation Failed")
                return False

            LOGGER.info("Server Creation Test PASSED !")
            return True
        except Exception as e:
            msg = 'test_server_create: %s error' % (e)
            LOGGER.error(msg)
            raise

    def tranfer_file_between_servers(self):
        """Creates a file in source server and transfer it to 
           the target server
        """
        try:
            # Get Datacenter ID
            datacenter_id = self.__get_datacenter_id(self.datacenter_name)
            if not datacenter_id:
                return False

            # List created servers
            the_servers = self.cloud_api.list_servers(
                datacenter_id=datacenter_id)
            server_list = the_servers['items']
            for server in server_list:
                if server['properties']['name'] == 'FrontEnd':
                    frontend_serverid = server['id']
                if server['properties']['name'] == 'BackEnd':
                    backend_serverid = server['id']

            # Get Required Server Ips
            public_ip_frontend = self.__get_ip(
                datacenter_id=datacenter_id,
                server_id=frontend_serverid,
                nic_name='nic1')
            LOGGER.info(
                'FrontEnd Server Public IP: {}'.format(public_ip_frontend))

            private_ip_backend = self.__get_ip(
                datacenter_id=datacenter_id,
                server_id=backend_serverid,
                nic_name='nic2')
            LOGGER.info(
                'BackEnd Server Private IP: {}'.format(private_ip_backend))

            LOGGER.info("Starting FronEnd Server Connection ...")
            with settings(host_string=public_ip_frontend,
                          user='root',
                          port=22,
                          password='Ubuntu123',
                          warn_only=True), hide('output', 'running'):
                # Create a file on source server of size 20 MB
                create_file_command = 'dd if=/dev/zero of=profitbricks.mov bs=20MB count=1'
                create_file_cmd_out = run(create_file_command, timeout=360)

                get_file_size_cmd = 'stat --printf="%s" profitbricks.mov'
                file_size_on_source = run(get_file_size_cmd, timeout=360)
                LOGGER.info(
                    "File of Size {} bytes is created on FrontEnd Server". \
                        format(file_size_on_source))

                # File transfer between source and target
                LOGGER.info("Doing SCP of file from FronEnd to BackServer ...")
                scp_file_cmd = 'scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no profitbricks.mov root@{0}:~/'. \
                    format(private_ip_backend)
                scp_file_cmd_out = run(scp_file_cmd, timeout=360)
                LOGGER.info(scp_file_cmd_out)

                # Check File is created on BackEnd Server
                get_file_size_cmd_on_target = 'ssh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@{} stat --printf="%s" profitbricks.mov'. \
                    format(private_ip_backend)
                file_size_on_target = run(get_file_size_cmd_on_target,
                                          timeout=360)
                LOGGER.info(
                    "File of Size {} bytes is transferred to BackEnd Server". \
                        format(file_size_on_target))

                LOGGER.info("Comparing Two File Sizes ...")
                if file_size_on_source == file_size_on_target:
                    LOGGER.info("File Tranfer Test PASSED")
                    return True

            LOGGER.error("File Tranfer Test FAILED")
            return False
        except Exception as e:
            msg = 'tranfer_file_between_servers: %s error' % (e)
            LOGGER.error(msg)
            raise

    def test_datacenter_update(self):
        """Updates a Datacenter resources :
           cpu core and ram of the servers
        """
        try:
            # Get Datacenter ID
            datacenter_id = self.__get_datacenter_id(self.datacenter_name)
            if not datacenter_id:
                return False

            # List of created servers
            the_servers = self.cloud_api.list_servers(
                datacenter_id=datacenter_id)
            server_list = the_servers['items']
            for server in server_list:
                if server['properties']['name'] == 'FrontEnd':
                    frontend_serverid = server['id']
                if server['properties']['name'] == 'BackEnd':
                    backend_serverid = server['id']

            server_id_list = [frontend_serverid, backend_serverid]
            updated_resource = {'cores': 3, 'ram': 4096}
            LOGGER.info('Updating Datacenter with resources : {}'.
                        format(updated_resource))
            for serverid in server_id_list:
                # Update Server resources
                update_response = self.cloud_api.update_server(
                    datacenter_id=datacenter_id,
                    server_id=serverid,
                    cores=updated_resource.get('cores'),
                    ram=updated_resource.get('ram'))
                self.cloud_api.poll_till_completion(update_response)

            test = True
            LOGGER.info("Verify the Resource Update ...")
            the_servers = self.cloud_api.list_servers(
                datacenter_id=datacenter_id)
            server_list = the_servers['items']
            for server in server_list:
                if server['properties']['cores'] != updated_resource.get(
                    'cores') \
                    or server['properties']['ram'] != updated_resource.get(
                    'ram'):
                    test = False
            if test:
                LOGGER.info("Datacenter Resource Update Test PASSED!")
                return True
            LOGGER.error("Datacenter Resource Update Test FAILED!")
            return False
        except Exception as e:
            msg = 'test_datacenter_update: %s error' % (e)
            LOGGER.error(msg)
            raise

    """ Private Methods """

    def __get_datacenter_id(self, datacenter_name):
        """Method to get DC id by DC name
        """
        LOGGER.info("Get Datacenter Id by name: {}".
                    format(datacenter_name))
        datacenter = self.cloud_api.get_datacenter_by_name(
            name=datacenter_name)
        if not datacenter:
            LOGGER.error("Datacenter by name: {} not found".
                         format(datacenter_name))
            return False
        datacenter_id = datacenter['id']
        return datacenter_id

    def __get_ip(self, datacenter_id, server_id, nic_name):
        """Method to return ip addr associated with nic of a server
        """
        the_nics = self.cloud_api.list_nics(datacenter_id=datacenter_id,
                                            server_id=server_id)

        for nic in the_nics['items']:
            if nic['properties']['name'] == nic_name:
                nicid = nic['id']

        nic_resp = self.cloud_api.get_nic(
            datacenter_id=datacenter_id,
            server_id=server_id,
            nic_id=nicid)
        if not nic_resp:
            return False
        return nic_resp['properties']['ips'][0]

    @classmethod
    def tearDownClass(self):
        pass


"""Test Runner """


def ProfitBricksQATestRunner():
    tests = [
        # QA Test 1
        'test_datacenter_create',
        # QA Test 2
        'test_server_create',
        ## QA Test 3
        'test_datacenter_update',
        ## QA Test 4
        'tranfer_file_between_servers'
    ]
    return unittest.TestSuite(map(ProfitBricksQATest, tests))


if __name__ == "__main__":
    unittest.main(defaultTest='ProfitBricksQATestRunner',
                  verbosity=2)
