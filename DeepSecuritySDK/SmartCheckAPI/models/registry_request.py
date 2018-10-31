# coding: utf-8

"""
    Deep Security Smart Check

    Deep Security Smart Check is a container image scanner from Trend Micro.   # noqa: E501

    OpenAPI spec version: 2018-05-01
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six

from SmartCheckAPI.models.inline_response20010_filter import InlineResponse20010Filter  # noqa: F401,E501
from SmartCheckAPI.models.registries_credentials import RegistriesCredentials  # noqa: F401,E501


class RegistryRequest(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'name': 'str',
        'description': 'str',
        'host': 'str',
        'credentials': 'RegistriesCredentials',
        'insecure_skip_verify': 'bool',
        'root_c_as': 'str',
        'filter': 'InlineResponse20010Filter',
        'schedule': 'bool'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'host': 'host',
        'credentials': 'credentials',
        'insecure_skip_verify': 'insecureSkipVerify',
        'root_c_as': 'rootCAs',
        'filter': 'filter',
        'schedule': 'schedule'
    }

    def __init__(self, name=None, description=None, host=None, credentials=None, insecure_skip_verify=None, root_c_as=None, filter=None, schedule=None):  # noqa: E501
        """RegistryRequest - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._host = None
        self._credentials = None
        self._insecure_skip_verify = None
        self._root_c_as = None
        self._filter = None
        self._schedule = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if host is not None:
            self.host = host
        if credentials is not None:
            self.credentials = credentials
        if insecure_skip_verify is not None:
            self.insecure_skip_verify = insecure_skip_verify
        if root_c_as is not None:
            self.root_c_as = root_c_as
        if filter is not None:
            self.filter = filter
        if schedule is not None:
            self.schedule = schedule

    @property
    def name(self):
        """Gets the name of this RegistryRequest.  # noqa: E501

        The name to display for the registry. If not specified, the registry `host` value will be used as the initial name.   # noqa: E501

        :return: The name of this RegistryRequest.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this RegistryRequest.

        The name to display for the registry. If not specified, the registry `host` value will be used as the initial name.   # noqa: E501

        :param name: The name of this RegistryRequest.  # noqa: E501
        :type: str
        """
        if name is not None and len(name) > 255:
            raise ValueError("Invalid value for `name`, length must be less than or equal to `255`")  # noqa: E501

        self._name = name

    @property
    def description(self):
        """Gets the description of this RegistryRequest.  # noqa: E501

        A longer-form note to attach to the registry.   # noqa: E501

        :return: The description of this RegistryRequest.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this RegistryRequest.

        A longer-form note to attach to the registry.   # noqa: E501

        :param description: The description of this RegistryRequest.  # noqa: E501
        :type: str
        """
        if description is not None and len(description) > 2048:
            raise ValueError("Invalid value for `description`, length must be less than or equal to `2048`")  # noqa: E501

        self._description = description

    @property
    def host(self):
        """Gets the host of this RegistryRequest.  # noqa: E501

        The host where the registry can be found. Required except when using Amazon Elastic Container Registry.   # noqa: E501

        :return: The host of this RegistryRequest.  # noqa: E501
        :rtype: str
        """
        return self._host

    @host.setter
    def host(self, host):
        """Sets the host of this RegistryRequest.

        The host where the registry can be found. Required except when using Amazon Elastic Container Registry.   # noqa: E501

        :param host: The host of this RegistryRequest.  # noqa: E501
        :type: str
        """
        if host is not None and len(host) > 255:
            raise ValueError("Invalid value for `host`, length must be less than or equal to `255`")  # noqa: E501

        self._host = host

    @property
    def credentials(self):
        """Gets the credentials of this RegistryRequest.  # noqa: E501


        :return: The credentials of this RegistryRequest.  # noqa: E501
        :rtype: RegistriesCredentials
        """
        return self._credentials

    @credentials.setter
    def credentials(self, credentials):
        """Sets the credentials of this RegistryRequest.


        :param credentials: The credentials of this RegistryRequest.  # noqa: E501
        :type: RegistriesCredentials
        """

        self._credentials = credentials

    @property
    def insecure_skip_verify(self):
        """Gets the insecure_skip_verify of this RegistryRequest.  # noqa: E501

        If `true`, Deep Security Smart Check will not verify TLS connections to the registry. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the registry are secured by other means.   # noqa: E501

        :return: The insecure_skip_verify of this RegistryRequest.  # noqa: E501
        :rtype: bool
        """
        return self._insecure_skip_verify

    @insecure_skip_verify.setter
    def insecure_skip_verify(self, insecure_skip_verify):
        """Sets the insecure_skip_verify of this RegistryRequest.

        If `true`, Deep Security Smart Check will not verify TLS connections to the registry. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the registry are secured by other means.   # noqa: E501

        :param insecure_skip_verify: The insecure_skip_verify of this RegistryRequest.  # noqa: E501
        :type: bool
        """

        self._insecure_skip_verify = insecure_skip_verify

    @property
    def root_c_as(self):
        """Gets the root_c_as of this RegistryRequest.  # noqa: E501

        (optional, default: `null`) If present, the service will use the provided root CAs as the trusted root CAs for registry requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the service will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :return: The root_c_as of this RegistryRequest.  # noqa: E501
        :rtype: str
        """
        return self._root_c_as

    @root_c_as.setter
    def root_c_as(self, root_c_as):
        """Sets the root_c_as of this RegistryRequest.

        (optional, default: `null`) If present, the service will use the provided root CAs as the trusted root CAs for registry requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the service will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :param root_c_as: The root_c_as of this RegistryRequest.  # noqa: E501
        :type: str
        """
        if root_c_as is not None and len(root_c_as) > 32768:
            raise ValueError("Invalid value for `root_c_as`, length must be less than or equal to `32768`")  # noqa: E501

        self._root_c_as = root_c_as

    @property
    def filter(self):
        """Gets the filter of this RegistryRequest.  # noqa: E501


        :return: The filter of this RegistryRequest.  # noqa: E501
        :rtype: InlineResponse20010Filter
        """
        return self._filter

    @filter.setter
    def filter(self, filter):
        """Sets the filter of this RegistryRequest.


        :param filter: The filter of this RegistryRequest.  # noqa: E501
        :type: InlineResponse20010Filter
        """

        self._filter = filter

    @property
    def schedule(self):
        """Gets the schedule of this RegistryRequest.  # noqa: E501

        If `true`, this registry will be scheduled for daily re-scan.   # noqa: E501

        :return: The schedule of this RegistryRequest.  # noqa: E501
        :rtype: bool
        """
        return self._schedule

    @schedule.setter
    def schedule(self, schedule):
        """Sets the schedule of this RegistryRequest.

        If `true`, this registry will be scheduled for daily re-scan.   # noqa: E501

        :param schedule: The schedule of this RegistryRequest.  # noqa: E501
        :type: bool
        """

        self._schedule = schedule

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, RegistryRequest):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
