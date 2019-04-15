import json
import logging
import re
import time

import requests

API_URL = 'https://api.profitbricks.com/cloudapi/v4'
USER_AGENT = "profitbricks-client"
logger = logging.getLogger(__name__)


class ProfitBricksApiLib(object):
    """
        ProfitBricksApiLib Class:
        To interact with ProfitBricks Cloud API
    """

    def __init__(self, username=None, password=None, base_url=API_URL):
        headers = dict()
        self.base_url = base_url
        self.headers = headers
        self.username = username
        self.password = password
        self.user_agent = '{}/{}'.format(USER_AGENT, '4.1.3')

    # API Operations 
    def get_datacenter(self, datacenter_id, depth=1):
        """Get a data center by its ID.
           :args      datacenter_id: The unique ID of the data center.
        """
        response = self._execute_request(
            '/datacenters/%s?depth=%s' % (datacenter_id, str(depth)))

        return response

    def get_datacenter_by_name(self, name, depth=1):
        """Gets a data center by its name.
           :args      datacenter_id: The unique ID of the data center.
        """
        all_data_centers = self.list_datacenters(depth=depth)['items']
        for data_centers in all_data_centers:
            if name in data_centers['properties']['name']:
                return data_centers

    def list_datacenters(self, depth=1):
        """Gets a list of all data centers.
        """
        response = self._execute_request('/datacenters?depth=' + str(depth))

        return response

    def delete_datacenter(self, datacenter_id):
        """Deletes the data center and all its components
           :args      datacenter_id: The unique ID of the data center.
        """
        response = self._execute_request(
            url='/datacenters/%s' % (datacenter_id),
            method='DELETE')

        return response

    def create_datacenter(self, datacenter):
        """Creates a data center
           :args      datacenter: A dict of data center data
        """
        lan_items = []
        entities = dict()
        properties = {
            "name": datacenter.get('name')
        }
        properties['location'] = datacenter.get('location')
        properties['description'] = datacenter.get('description')

        # LANs
        if len(datacenter.get('lans')) > 0:
            for lan in datacenter.get('lans'):
                lan_items.append(
                    self._create_lan_dict(lan)
                )
            lans = {
                "items": lan_items
            }
            lan_entities = {
                "lans": lans
            }

            entities.update(lan_entities)

        if len(entities) == 0:
            raw_data = {
                "properties": properties,
            }
        else:
            raw_data = {
                "properties": properties,
                "entities": entities
            }

        data = json.dumps(raw_data)

        response = self._execute_request(
            url='/datacenters',
            method='POST',
            data=data)

        return response

    def list_images(self, depth=1):
        """Gets a list of images available in the data center.
        """
        response = self._execute_request('/images?depth=' + str(depth))
        return response

    def list_lans(self, datacenter_id, depth=1):
        """Gets a list of LANs available.
           :args      datacenter_id: The unique ID of the data center.
        """
        response = self._execute_request(
            '/datacenters/%s/lans?depth=%s' % (
                datacenter_id,
                str(depth)))

        return response

    def get_nic(self, datacenter_id, server_id, nic_id, depth=1):
        """Gets a NIC by its ID.
           :args      datacenter_id: The unique ID of the data center.
           :args      server_id: The unique ID of the server.
           :args      nic_id: The unique ID of the NIC.
        """
        response = self._execute_request(
            '/datacenters/%s/servers/%s/nics/%s?depth=%s' % (
                datacenter_id,
                server_id,
                nic_id,
                str(depth)))

        return response

    def list_nics(self, datacenter_id, server_id, depth=1):
        """Gets a list of all NICs in a server.
           :args      datacenter_id: The unique ID of the data center.
           :args      server_id: The unique ID of the server.
           :args      depth: The depth of the response data.
        """
        response = self._execute_request(
            '/datacenters/%s/servers/%s/nics?depth=%s' % (
                datacenter_id,
                server_id,
                str(depth)))

        return response

    def get_request(self, request_id, status=False):
        """Gets a single request by ID.
        """
        if status:
            response = self._execute_request(
                '/requests/' + request_id + '/status')
        else:
            response = self._execute_request(
                '/requests/%s' % request_id)

        return response

    def list_servers(self, datacenter_id, depth=1):
        """Gets a list of all servers bound to the specified data center.
            :args      datacenter_id: The unique ID of the data center.
            :args      depth: The depth of the response data.
        """
        response = self._execute_request(
            '/datacenters/%s/servers?depth=%s' % (datacenter_id, str(depth)))

        return response

    def create_server(self, datacenter_id, server):
        """Creates a server within the data center.
           :args      datacenter_id: The unique ID of the data center.
           :args      server: A dict of the server to be created.
        """

        data = json.dumps(self._create_server_dict(server))

        response = self._execute_request(
            url='/datacenters/%s/servers' % (datacenter_id),
            method='POST',
            data=data)

        return response

    def update_server(self, datacenter_id, server_id, **kwargs):
        """Updates a server with the argseters provided.
           :args      datacenter_id: The unique ID of the data center.
           :args      server_id: The unique ID of the server.
        """
        data = {}

        for attr in kwargs.keys():
            data[self._underscore_to_camelcase(attr)] = kwargs[attr]

        response = self._execute_request(
            url='/datacenters/%s/servers/%s' % (
                datacenter_id,
                server_id),
            method='PATCH',
            data=json.dumps(data))

        return response

    def poll_till_completion(self, response, timeout=3600, initial_wait=5,
                             scaleup=10):
        """Poll resource request status until resource is provisioned.
        """
        if not response:
            return

        wait_period = initial_wait
        next_increase = time.time() + wait_period * scaleup
        if timeout:
            timeout = time.time() + timeout
        while True:
            request = self.get_request(request_id=response['requestId'],
                                       status=True)

            if request['metadata']['status'] == 'DONE':
                break
            elif request['metadata']['status'] == 'FAILED':
                logger.error(
                    'Request {0} failed to complete: {1}'.format(
                        response['requestId'], request['metadata']['message']),
                    response['requestId']
                )

            current_time = time.time()
            if timeout and current_time > timeout:
                logger.error('Timed out waiting for request {0}.'.format(
                    response['requestId']), response['requestId'])

            if current_time > next_increase:
                wait_period *= 2
                next_increase = time.time() + wait_period * scaleup
                scaleup *= 2

            logger.info(
                "Request %s is in state '%s'. Sleeping for %i seconds...",
                response['requestId'], request['metadata']['status'],
                wait_period)
            time.sleep(wait_period)

    def _initiate_request(self, method, url,
                          argss=None,
                          data=None,
                          headers=None,
                          cookies=None,
                          files=None,
                          auth=None,
                          timeout=None,
                          allow_redirects=True,
                          proxies=None,
                          hooks=None,
                          stream=None):
        headers.update(self.headers)
        session = requests.Session()
        return session.request(method, url, argss, data, headers, cookies,
                               files, auth, timeout, allow_redirects, proxies,
                               hooks, stream)

    def _execute_request(self, url, method='GET', data=None, headers=None):
        if headers is None:
            headers = dict()

        auth = (self.username, self.password)

        url = self._compose_url(url)
        headers.update({'User-Agent': self.user_agent})
        if method == 'POST' or method == 'PUT':
            response = self._initiate_request(method, url, auth=auth,
                                              data=data,
                                              headers=headers)
            headers.update({'Content-Type': 'application/json'})
        elif method == 'POST-ACTION-JSON' or method == 'POST-ACTION':
            headers.update({
                               'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            response = self._initiate_request('POST', url, auth=auth,
                                              data=data,
                                              headers=headers)
            if response.status_code == 202 and method == 'POST-ACTION':
                return True
            elif response.status_code == 401:
                raise response.raise_for_status()
        elif method == 'PATCH':
            headers.update({'Content-Type': 'application/json'})
            response = self._initiate_request(method, url, auth=auth,
                                              data=data,
                                              headers=headers)
        else:
            headers.update({'Content-Type': 'application/json'})
            response = self._initiate_request(method, url, auth=auth,
                                              argss=data,
                                              headers=headers)
            if method == 'DELETE':
                if response.status_code == 202:
                    return True

        try:
            if not response.ok:
                err = response.json()
                code = err['httpStatus']
                msg = err['messages']
                logger.error(
                    "API Operation failed Error: {0}, {1}, {2}".format(code,
                                                                       msg,
                                                                       url))

        except ValueError:
            raise Exception('Failed to parse the response', response.text)

        json_response = response.json()

        if 'location' in response.headers:
            json_response['requestId'] = self._request_id(response.headers)

        return json_response

    @staticmethod
    def _request_id(headers):
        match = re.search('/requests/([-A-Fa-f0-9]+)/', headers['location'])
        if match:
            return match.group(1)
        else:
            raise Exception("Failed to extract request ID from response "
                            "header 'location': '{location}'".format(
                location=headers['location']))

    def _compose_url(self, uri):
        url = self.base_url + uri
        return url

    @staticmethod
    def _underscore_to_camelcase(value):
        """
        Convert Python snake case back to mixed case.
        """

        def camelcase():
            yield str.lower
            while True:
                yield str.capitalize

        c = camelcase()
        return "".join(next(c)(x) if x else '_' for x in value.split("_"))

    @staticmethod
    def _create_lan_dict(lan):
        items = []
        entities = dict()
        properties = {
            "name": lan.get("name")
        }
        if lan["public"] is not None:
            properties['public'] = str(lan.get("public")).lower()
        if len(entities) == 0:
            raw_data = {
                "properties": properties,
            }
        else:
            raw_data = {
                "properties": properties,
                "entities": entities
            }
        return raw_data

    def _create_nic_dict(self, nic):
        items = []
        properties = {
            "name": nic.get("name")
        }
        properties['lan'] = nic.get("lan")
        properties['dhcp'] = nic.get("dhcp")
        properties['firewallActive'] = nic.get("firewall_active")
        if len(nic.get("firewall_rules")) > 0:
            for rule in nic.get("firewall_rules"):
                items.append(self._create_firewallrules_dict(rule))
        rules = {
            "items": items
        }
        entities = {
            "firewallrules": rules
        }
        raw_data = {
            "properties": properties,
            "entities": entities
        }
        return raw_data

    @staticmethod
    def _create_firewallrules_dict(rule):
        properties = {}
        properties['name'] = rule.get('name')
        properties['protocol'] = rule.get('protocol')
        properties['sourceIp'] = rule.get('source_ip')
        properties['portRangeStart'] = rule.get('port_range_start')
        properties['portRangeEnd'] = rule.get('port_range_end')
        raw_data = {
            "properties": properties
        }
        return raw_data

    def _create_server_dict(self, server):
        volume_items = []
        nic_items = []
        entities = dict()
        properties = {
            "name": server.get('name')
        }
        properties['ram'] = server.get('ram')
        properties['cores'] = server.get('cores')
        if len(server.get('create_volumes')) > 0:
            for volume in server.get('create_volumes'):
                volume_items.append(self._create_volume_dict(volume))
            volumes = {
                "items": volume_items
            }
            volume_entities = {
                "volumes": volumes
            }
            entities.update(volume_entities)
        if len(server.get('nics')) > 0:
            for nic in server.get('nics'):
                nic_items.append(self._create_nic_dict(nic))
            nics = {
                "items": nic_items
            }
            nic_entities = {
                "nics": nics
            }
            entities.update(nic_entities)
        if len(entities) == 0:
            raw_data = {
                "properties": properties,
            }
        else:
            raw_data = {
                "properties": properties,
                "entities": entities
            }
        return raw_data

    @staticmethod
    def _create_volume_dict(volume):
        properties = {
            "name": volume.get('name')
        }
        properties['size'] = int(volume.get('size'))
        properties['availabilityZone'] = volume.get('availability_zone')
        properties['image'] = volume.get('image')
        properties['bus'] = volume.get('bus')
        properties['type'] = volume.get('disk_type')
        properties['imagePassword'] = volume.get('image_password')
        properties['sshKeys'] = volume.get('ssh_keys')
        raw_data = {
            "properties": properties
        }
        return raw_data
