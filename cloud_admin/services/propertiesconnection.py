
import json
import re

import boto
from boto.connection import AWSQueryConnection

from cloud_admin.services import EucaNotFoundException
from cloud_admin.services.eucaproperty import (
    EucaProperty,
    SHOW_PROPERTIES,
    SHOW_PROPERTIES_NARROW
)
from cloud_utils.log_utils import eulogger

###############################################################################################
#                       Eucalyptus Admin ('Properties') Query Interface                       #
###############################################################################################


class PropertiesConnection(AWSQueryConnection):
    APIVersion = 'eucalyptus'

    def __init__(self,
                 hostname,
                 aws_access_key,
                 aws_secret_key,
                 path='/services/Properties',
                 port=8773,
                 is_secure=False,
                 boto_debug_level=0,
                 err_method=None,
                 logger=None,
                 **kwargs):
        """
        Primary Admin/Properties Query interface for a Eucalyptus Cloud

        :param hostname: service endpoint, hostname, ip, etc..
        :param access_key: cloud user access key to auth this connection
        :param secret_key: cloud user secret key to auth this connection
        :param port: remote port to be used for this connection
        :param path: service path for this connection
        :param is_secure: bool
        :param boto_debug_level: int 0-2
        :param debug_method: method to be used for logging debug information
        :param err_method:  method to be used for logging error information
        :param kwargs: Additional kwargs to be passed to connection init
        :raise ValueError: Upon or invalid params
        """

        # Note: aws_access and secret_key get assigned to self during super().__init__()
        self.host = hostname
        if not isinstance(self.host, basestring) or \
                not isinstance(aws_access_key, basestring) or \
                not isinstance(aws_secret_key, basestring):
            raise ValueError('Missing or invalid type for required arg. host:"{0}", '
                             'aws_access_key_id:"{1}", aws_secret_access_key:"{2}"'
                             .format(self.host,
                                     aws_access_key,
                                     aws_secret_key))
        self.is_secure = is_secure
        self.port = port
        self.path = path
        # debug is an int representation of the debug level. Use log.debug() for
        # logging debug information
        self.debug = boto_debug_level
        if self.debug:
            boto.set_stream_logger('boto')
        if not logger:
            logger = eulogger.Eulogger(identifier=self.__repr__())
        self.log = logger
        self._show_method = self.log.info
        self.debug_method = self.log.debug
        if err_method:
            self.err_method = err_method
        super(PropertiesConnection, self).__init__(path=self.path,
                                                   aws_access_key_id=aws_access_key,
                                                   aws_secret_access_key=aws_secret_key,
                                                   port=self.port,
                                                   is_secure=self.is_secure,
                                                   host=self.host,
                                                   debug=self.debug,
                                                   **kwargs)

    def __repr__(self):
        return "{0}:{1}".format(self.host, self.__class__.__name__)

    def err_method(self, msg):
        '''
        The default error logging method to be used if a 'debug_method' or 'tester' obj
        was not provided at init overwriting this method.
        '''
        self.log.error(msg)

    def _get_list_request(self, action, service=EucaProperty, params={},
                          markers=['item', 'euca:item'], verb='GET'):
        """
        Make list request and parse objects into provided 'service' class using provided 'markers'

        :param action: requested action
        :param service: class used to parse response
        :param params: dict of parameters used in request
        :param markers: list markers for parsing response xml into provided service class
        :param verb: verb used in request, default: 'GET'
        :return: list of obj of type defined by provided 'service' class kwarg
        """
        params = params
        new_markers = []
        for marker in markers:
            new_markers.append((marker, service))
        return self.get_list(action, params, new_markers, verb=verb)

    ###############################################################################################
    #                            Eucalyptus 'Property' Methods                                    #
    ###############################################################################################

    def get_property(self, property):
        """
        Gets a single eucalyptus property matching 'property'.
        If the query returns anything other than a single property, a ValueError is thrown.

        :params property: string representing the property name,
                          or EucaProperty obj used to fetch the eucalyptus property
        :returns : A single EucaProperty obj
        """
        property_name = None
        if property:
            if isinstance(property, EucaProperty):
                property_name = property.name
            if isinstance(property, basestring):
                property_name = str(property)
        if not property:
            raise ValueError('Unknown type provided for property lookup: "{0}/{1}"'
                             .format(property, type(property)))
        props = self.get_properties(property_name)
        keep = []
        for prop in props:
            if re.match('^{0}$'.format(property_name), prop.name):
                keep.append(prop)
        prop_count = len(keep)
        if prop_count < 1:
            raise EucaNotFoundException('get_property:Property not Found', {'property': property})
        if prop_count > 1:
            prop_string = ""
            try:
                prop_string = ",".join("\t{0}\n".format(x.name) for x in keep)
            except:
                pass
            raise ValueError('get_property: Multiple matches for property name:{0}, found {1} '
                             'matches:\n{2}'.format(property_name, prop_count, prop_string))
        return keep[0]

    def get_properties(self, search=None, *nameprefix):
        '''
        Gets eucalyptus cloud configuration properties
        examples:
            get_properties()
            get_properties('www', 'objectstorage')
            get_properties('cloud.euca_log_level')
        :param nameprefix: list or property names or the prefix to match against properties.
        :returns a list of EucaProperty objs
        '''
        ret_list = []
        params = {}
        x = 0
        nameprefix = nameprefix or []
        for prop in nameprefix:
            if not prop:
                continue
            x += 1
            params['Property.{0}'.format(x)] = prop
        props = self._get_list_request('DescribeProperties', params=params)
        if not search:
            return props
        for prop in props:
            if re.search(search, prop.name):
                ret_list.append(prop)
        return ret_list

    def modify_property(self, prop, value, verbose=True):
        """
        Modify a Eucalyptus Property

        :param prop: EucaProperty obj or string name of property
        :param value: value to modify property value to
        :param verbose: show debug information during modify attempt
        :return: Modified EucaProperty object
        :raise ValueError:
        """
        ret_prop = None
        params = {}
        action = 'ModifyPropertyValue'
        value = value or ""
        if not isinstance(prop, EucaProperty):
            props = self.get_properties(prop) or []
            if props:
                prop = props[0]
            else:
                raise ValueError('modify_property err. Property: "{0}" was not found on system?'
                                 .format(prop))
        params['Name'] = prop.name
        params['Value'] = str(value)
        markers = ['euca:ModifyPropertyValueResponseType', 'ModifyPropertyValueResponseType']
        ret_prop_list = self._get_list_request(action=action, verb='POST', params=params, markers=markers)
        if ret_prop_list:
            ret_prop = ret_prop_list[0]
            if verbose:
                self.show_properties(properties=[ret_prop], description=False)
        else:
            if verbose:
                self.debug_method('Could not parse EucaProperty from ModifyPropertyValue '
                                  'response:"{0}"'.format(prop))
        return ret_prop

    def show_properties(self, *args, **kwargs):
        '''
        Summarize Eucalyptus properties in table format

        :param properties: list of property names, or Eucaproperties to summarize
        :param description: bool, show property descriptions
        :param grid: bool, show table in grid format
        :param readonly: bool, show readonly flag
        :param defaults: bool, show property defaults in table
        :param print_table: bool, if True will print table using connection.debug_method()
                            if False will return the table object
        :param search: string, to use as filter for name of properties
        :param nameprefix: property names used to filter query responsee
        '''
        return SHOW_PROPERTIES(self, *args, **kwargs)

    def show_properties_narrow(self, *args, **kwargs):
        """
        Narrow formatted table used to summarize Eucalyptus properties

        :param connection: cloud_admin connection
        :param properties: list of EucaProperty objs or string names of properties
        :param verbose: show debug information during table creation
        :param print_table: bool, if True will print table using connection.debug_method()
                            if False will return the table object
        :param prop_names: property names used to filter query response
        """
        return SHOW_PROPERTIES_NARROW(self, *args, **kwargs)

    def get_cloud_network_config_json(self, property_name='cloud.network.network_configuration'):
        net_prop = self.get_property(property=property_name)
        return json.loads(net_prop.value)

    def modify_cloud_network_config_json(self, net_dict,
                                         property_name='cloud.network.network_configuration'):
        net_prop = self.get_property(property=property_name)
        last_value = net_prop.value
        if isinstance(net_dict, dict):
            net_dict = json.dumps(net_dict, format=2)
        if not isinstance(net_dict, basestring):
            raise ValueError('modify_cloud_network_config_json: net_dict not string or json')
        self.modify_property(net_prop, net_dict)

