# stdlib
import json
import ssl

# requests
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

# keen
from keen import exceptions, utilities
from keen.utilities import KeenKeys, requires_key

# json
from requests.compat import json


__author__ = 'dkador'


class HTTPMethods(object):

    """ HTTP methods that can be used with Keen's API. """

    GET = 'get'
    POST = 'post'
    DELETE = 'delete'
    PUT = 'put'


class KeenAdapter(HTTPAdapter):

    """ Adapt :py:mod:`requests` to Keen IO. """

    def init_poolmanager(self, connections, maxsize, block=False):

        """ Initialize pool manager with forced TLSv1 support. """

        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)


class KeenApi(object):
    """
    Responsible for communicating with the Keen API. Used by multiple
    persistence strategies or async processing.
    """

    # the default base URL of the Keen API
    base_url = "https://api.keen.io"

    # the default version of the Keen API
    api_version = "3.0"

    # self says it belongs to KeenApi/andOr is the object passed into KeenApi
    # __init__ create keenapi object whenever KeenApi class is invoked
    def __init__(self, project_id, write_key=None, read_key=None,
                 base_url=None, api_version=None, get_timeout=None, post_timeout=None,
                 master_key=None):
        """
        Initializes a KeenApi object

        :param project_id: the Keen project ID
        :param write_key: a Keen IO Scoped Key for Writes
        :param read_key: a Keen IO Scoped Key for Reads
        :param base_url: optional, set this to override where API requests
        are sent
        :param api_version: string, optional, set this to override what API
        version is used
        :param get_timeout: optional, the timeout on GET requests
        :param post_timeout: optional, the timeout on POST requests
        :param master_key: a Keen IO Master API Key, needed for deletes
        """
        # super? recreates the object with values passed into KeenApi
        super(KeenApi, self).__init__()
        self.project_id = project_id
        self.write_key = write_key
        self.read_key = read_key
        self.master_key = master_key
        if base_url:
            self.base_url = base_url
        if api_version:
            self.api_version = api_version
        self.get_timeout = get_timeout
        self.post_timeout = post_timeout
        self.session = self._create_session()

    def fulfill(self, method, *args, **kwargs):

        """ Fulfill an HTTP request to Keen's API. """

        return getattr(self.session, method)(*args, **kwargs)

    @requires_key(KeenKeys.WRITE)
    def post_event(self, event):
        """
        Posts a single event to the Keen IO API. The write key must be set first.

        :param event: an Event to upload
        """

        url = "{0}/{1}/projects/{2}/events/{3}".format(self.base_url, self.api_version,
                                                       self.project_id,
                                                       event.event_collection)
        headers = utilities.headers(self.write_key)
        payload = event.to_json()
        response = self.fulfill(HTTPMethods.POST, url, data=payload, headers=headers, timeout=self.post_timeout)
        self._error_handling(response)

    @requires_key(KeenKeys.WRITE)
    def post_events(self, events):

        """
        Posts a single event to the Keen IO API. The write key must be set first.

        :param events: an Event to upload
        """

        url = "{0}/{1}/projects/{2}/events".format(self.base_url, self.api_version,
                                                   self.project_id)
        headers = utilities.headers(self.write_key)
        payload = json.dumps(events)
        response = self.fulfill(HTTPMethods.POST, url, data=payload, headers=headers, timeout=self.post_timeout)
        self._error_handling(response)
        return self._get_response_json(response)

    @requires_key(KeenKeys.READ)
    def query(self, analysis_type, params, all_keys=False):
        """
        Performs a query using the Keen IO analysis API.  A read key must be set first.

        """

        url = "{0}/{1}/projects/{2}/queries/{3}".format(self.base_url, self.api_version,
                                                        self.project_id, analysis_type)

        headers = utilities.headers(self.read_key)
        payload = params
        response = self.fulfill(HTTPMethods.GET, url, params=payload, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)

        response = response.json()

        if not all_keys:
            response = response["result"]

        return response

    @requires_key(KeenKeys.MASTER)
    def delete_events(self, event_collection, params):
        """
        Deletes events via the Keen IO API. A master key must be set first.

        :param event_collection: string, the event collection from which event are being deleted

        """

        url = "{0}/{1}/projects/{2}/events/{3}".format(self.base_url,
                                                       self.api_version,
                                                       self.project_id,
                                                       event_collection)
        headers = utilities.headers(self.master_key)
        response = self.fulfill(HTTPMethods.DELETE, url, params=params, headers=headers, timeout=self.post_timeout)

        self._error_handling(response)
        return True

    @requires_key(KeenKeys.READ)
    def get_collection(self, event_collection):
        """
        Extracts info about a collection using the Keen IO API. A master key must be set first.

        :param event_collection: the name of the collection to retrieve info for
        """

        url = "{0}/{1}/projects/{2}/events/{3}".format(self.base_url, self.api_version,
                                                       self.project_id, event_collection)
        headers = utilities.headers(self.read_key)
        response = self.fulfill(HTTPMethods.GET, url, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)

        return response.json()

    @requires_key(KeenKeys.READ)
    def get_all_collections(self):
        """
        Extracts schema for all collections using the Keen IO API. A read key must be set first.

        """

        url = "{0}/{1}/projects/{2}/events".format(self.base_url, self.api_version, self.project_id)
        headers = utilities.headers(self.read_key)
        response = self.fulfill(HTTPMethods.GET, url, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)

        return response.json()

    @requires_key(KeenKeys.MASTER)
    def create_access_key(self, name, is_active=True, permitted=[], options={}):
        """
        Creates a new access key. A master key must be set first.

        :param name: the name of the access key to create
        :param is_active: Boolean value dictating whether this key is currently active (default True)
        :param permitted: list of strings describing which operation types this key will permit
                          Legal values include "writes", "queries", "saved_queries", "cached_queries",
                          "datasets", and "schema".
        :param options: dictionary containing more details about the key's permitted and restricted
                        functionality
        """

        url = "{0}/{1}/projects/{2}/keys".format(self.base_url, self.api_version, self.project_id)
        headers = utilities.headers(self.master_key)

        payload_dict = {
            "name": name,
            "is_active": is_active,
            "permitted": permitted,
            "options": options
        }
        payload = json.dumps(payload_dict)

        response = self.fulfill(HTTPMethods.POST, url, data=payload, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)
        return response.json()

    @requires_key(KeenKeys.MASTER)
    def list_access_keys(self):
        """
        Returns a list of all access keys in this project. A master key must be set first.
        """
        url = "{0}/{1}/projects/{2}/keys".format(self.base_url, self.api_version, self.project_id)
        headers = utilities.headers(self.master_key)
        response = self.fulfill(HTTPMethods.GET, url, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)

        return response.json()

    @requires_key(KeenKeys.MASTER)
    def get_access_key(self, access_key_id):
        """
        Returns details on a particular access key. A master key must be set first.

        :param access_key_id: the 'key' value of the access key to retreive data from
        """
        url = "{0}/{1}/projects/{2}/keys/{3}".format(self.base_url, self.api_version, self.project_id,
                                                     access_key_id)
        headers = utilities.headers(self.master_key)
        response = self.fulfill(HTTPMethods.GET, url, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)

        return response.json()

    def _build_access_key_dict(access_key):
        """
        Populates a dictionary payload usable in a POST request from a full access key object.

        :param access_key: the access_key to copy data from
        """
        return {
            "name": access_key["name"],
            "is_active": access_key["is_active"],
            "permitted": access_key["permitted"],
            "options": access_key["options"]
        }

    def _update_access_key_pair(self, access_key_id, key, val):
        """
        Helper for updating access keys in a DRY fashion.
        """
        # Get current state via HTTPS.
        current_access_key = self.get_access_key(access_key_id)

        # Copy and only change the single parameter.
        payload_dict = self._build_access_key_dict(current_access_key)
        payload_dict[key] = val

        # Now just treat it like a full update.
        return self.update_access_key_full(access_key_id, **payload_dict)

    @requires_key(KeenKeys.MASTER)
    def update_access_key_name(self, access_key_id, name):
        """
        Updates only the name portion of an access key.

        :param access_key_id: the 'key' value of the access key to change the name of
        :param name: the new name to give this access key
        """
        return self._update_access_key_pair(access_key_id, "name", name)
        
    @requires_key(KeenKeys.MASTER)
    def add_access_key_permissions(self, access_key_id, permissions):
        """
        Adds to the existing list of permissions on this key with the contents of this list.
        Will not remove any existing permissions or modify the remainder of the key.

        :param access_key_id: the 'key' value of the access key to add permissions to
        :param permissions: the new permissions to add to the existing list of permissions
        """
        # Get current state via HTTPS.
        current_access_key = self.get_access_key(access_key_id)

        # Copy and only change the single parameter.
        payload_dict = self._build_access_key_dict(current_access_key)

        # Turn into sets to avoid duplicates.
        old_permissions = set(payload_dict["permissions"])
        new_permissions = set(permissions)
        combined_permissions = old_permissions.union(new_permissions)
        payload_dict["permissions"] = list(combined_permissions)

        # Now just treat it like a full update.
        return self.update_access_key_full(access_key_id, **payload_dict)

    @requires_key(KeenKeys.MASTER)
    def remove_access_key_permissions(self, access_key_id, permissions):
        """
        Removes a list of permissions from the existing list of permissions.
        Will not remove all existing permissions unless all such permissions are included
        in this list. Not to be confused with key revocation.

        See also: revoke_access_key()

        :param access_key_id: the 'key' value of the access key to remove some permissions from
        :param permissions: the permissions you wish to remove from this access key
        """
        # Get current state via HTTPS.
        current_access_key = self.get_access_key(access_key_id)

        # Copy and only change the single parameter.
        payload_dict = self._build_access_key_dict(current_access_key)

        # Turn into sets to avoid duplicates.
        old_permissions = set(payload_dict["permissions"])
        removal_permissions = set(permissions)
        reduced_permissions = old_permissions.difference_update(removal_permissions)
        payload_dict["permissions"] = list(reduced_permissions)

        # Now just treat it like a full update.
        return self.update_access_key_full(access_key_id, **payload_dict)

    @requires_key(KeenKeys.MASTER)
    def update_access_key_permissions(self, access_key_id, permissions):
        """
        Replaces all of the permissions on the access key but does not change
        non-permission properties such as the key's name.

        See also: add_access_key_permissions() and remove_access_key_permissions().

        :param access_key_id: the 'key' value of the access key to change the permissions of
        :param permissions: the new list of permissions for this key
        """
        return self._update_access_key_pair(access_key_id, "permissions", permission)

    @requires_key(KeenKeys.MASTER)
    def update_access_key_options(self, access_key_id, options):
        """
        Replaces all of the options on the access key but does not change
        non-option properties such as permissions or the key's name.

        :param access_key_id: the 'key' value of the access key to change the options of
        :param options: the new dictionary of options for this key
        """
        return self._update_access_key_pair(access_key_id, "options", options)


    @requires_key(KeenKeys.MASTER)
    def update_access_key_full(self, access_key_id, name, is_active, permitted, options):
        """
        Replaces the 'name', 'is_active', 'permitted', and 'options' values of a given key.
        A master key must be set first.

        :param access_key_id: the 'key' value of the access key for which the values will be replaced
        :param name: the new name desired for this access key
        :param is_active: whether the key should become enabled (True) or revoked (False)
        :param permitted: the new list of permissions desired for this access key
        :param options: the new dictionary of options for this access key
        """
        url = "{0}/{1}/projects/{2}/keys/{3}".format(self.base_url, self.api_version,
                                                     self.project_id, access_key_id)
        headers = utilities.headers(self.master_key)
        payload_dict = {
            "name": name,
            "is_active": is_active,
            "permitted": permitted,
            "options": options
        }
        payload = json.dumps(payload_dict)
        response = self.fulfill(HTTPMethods.POST, url, data=payload, headers=headers, timeout=self.get_timeout)
        self._error_handling(response)
        return response.json()

    @requires_key(KeenKeys.MASTER)
    def revoke_access_key(self, access_key_id):
        """
        Revokes an access key. "Bad dog! No biscuit!"

        :param access_key_id: the 'key' value of the access key to revoke
        """
        url = "{0}/{1}/projects/{2}/keys/{3}/revoke".format(self.base_url, self.api_version,
                                                            self.project_id, access_key_id)
        headers = utilities.headers(self.master_key)
        response = self.fulfill(HTTPMethods.POST, url, headers=headers, timeout=self.get_timeout)

        self._error_handling(response)
        return response.json()

    @requires_key(KeenKeys.MASTER)
    def unrevoke_access_key(self, access_key_id):
        """
        Re-enables an access key.

        :param access_key_id: the 'key' value of the access key to re-enable (unrevoke)
        """
        url = "{0}/{1}/projects/{2}/keys/{3}/unrevoke".format(self.base_url, self.api_version,
                                                              self.project_id, access_key_id)
        headers = utilities.headers(self.master_key)
        response = self.fulfill(HTTPMethods.POST, url, headers=headers, timeout=self.get_timeout)

        self._error_handling(response)
        return response.json()

    def _error_handling(self, res):
        """
        Helper function to do the error handling

        :params res: the response from a request
        """

        # making the error handling generic so if an status_code starting with 2 doesn't exist, we raise the error
        if res.status_code // 100 != 2:
            error = self._get_response_json(res)
            raise exceptions.KeenApiError(error)

    def _get_response_json(self, res):
        """
        Helper function to extract the JSON body out of a response OR throw an exception.

        :param res: the response from a request
        :return: the JSON body OR throws an exception
        """

        try:
            error = res.json()
        except ValueError:
            error = {
                "message": "The API did not respond with JSON, but: {0}".format(res.text[:1000]),
                "error_code": "{0}".format(res.status_code)
            }
        return error

    def _create_session(self):

        """ Build a session that uses KeenAdapter for SSL """

        s = requests.Session()
        s.mount('https://', KeenAdapter())
        return s

    def _get_read_key(self):
        return self.read_key

    def _get_write_key(self):
        return self.write_key

    def _get_master_key(self):
        return self.master_key