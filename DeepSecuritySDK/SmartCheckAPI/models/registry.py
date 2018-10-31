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
from SmartCheckAPI.models.inline_response20010_metrics import InlineResponse20010Metrics  # noqa: F401,E501


class Registry(object):
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
        'id': 'str',
        'href': 'str',
        'name': 'str',
        'description': 'str',
        'host': 'str',
        'insecure_skip_verify': 'bool',
        'root_c_as': 'str',
        'filter': 'InlineResponse20010Filter',
        'metrics': 'InlineResponse20010Metrics',
        'schedule': 'bool',
        'status': 'str',
        'status_detail': 'str',
        'created': 'str',
        'updated': 'str'
    }

    attribute_map = {
        'id': 'id',
        'href': 'href',
        'name': 'name',
        'description': 'description',
        'host': 'host',
        'insecure_skip_verify': 'insecureSkipVerify',
        'root_c_as': 'rootCAs',
        'filter': 'filter',
        'metrics': 'metrics',
        'schedule': 'schedule',
        'status': 'status',
        'status_detail': 'statusDetail',
        'created': 'created',
        'updated': 'updated'
    }

    def __init__(self, id=None, href=None, name=None, description=None, host=None, insecure_skip_verify=None, root_c_as=None, filter=None, metrics=None, schedule=None, status=None, status_detail=None, created=None, updated=None):  # noqa: E501
        """Registry - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._href = None
        self._name = None
        self._description = None
        self._host = None
        self._insecure_skip_verify = None
        self._root_c_as = None
        self._filter = None
        self._metrics = None
        self._schedule = None
        self._status = None
        self._status_detail = None
        self._created = None
        self._updated = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if href is not None:
            self.href = href
        self.name = name
        if description is not None:
            self.description = description
        if host is not None:
            self.host = host
        if insecure_skip_verify is not None:
            self.insecure_skip_verify = insecure_skip_verify
        if root_c_as is not None:
            self.root_c_as = root_c_as
        if filter is not None:
            self.filter = filter
        if metrics is not None:
            self.metrics = metrics
        if schedule is not None:
            self.schedule = schedule
        self.status = status
        if status_detail is not None:
            self.status_detail = status_detail
        self.created = created
        self.updated = updated

    @property
    def id(self):
        """Gets the id of this Registry.  # noqa: E501

        The registry ID.   # noqa: E501

        :return: The id of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this Registry.

        The registry ID.   # noqa: E501

        :param id: The id of this Registry.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def href(self):
        """Gets the href of this Registry.  # noqa: E501

        The URL at which the registry can be found.   # noqa: E501

        :return: The href of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._href

    @href.setter
    def href(self, href):
        """Sets the href of this Registry.

        The URL at which the registry can be found.   # noqa: E501

        :param href: The href of this Registry.  # noqa: E501
        :type: str
        """

        self._href = href

    @property
    def name(self):
        """Gets the name of this Registry.  # noqa: E501

        The name to display for the registry.   # noqa: E501

        :return: The name of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this Registry.

        The name to display for the registry.   # noqa: E501

        :param name: The name of this Registry.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501
        if name is not None and len(name) > 255:
            raise ValueError("Invalid value for `name`, length must be less than or equal to `255`")  # noqa: E501

        self._name = name

    @property
    def description(self):
        """Gets the description of this Registry.  # noqa: E501

        A longer-form note to attach to the registry.   # noqa: E501

        :return: The description of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this Registry.

        A longer-form note to attach to the registry.   # noqa: E501

        :param description: The description of this Registry.  # noqa: E501
        :type: str
        """
        if description is not None and len(description) > 2048:
            raise ValueError("Invalid value for `description`, length must be less than or equal to `2048`")  # noqa: E501

        self._description = description

    @property
    def host(self):
        """Gets the host of this Registry.  # noqa: E501

        The host where the registry can be found.   # noqa: E501

        :return: The host of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._host

    @host.setter
    def host(self, host):
        """Sets the host of this Registry.

        The host where the registry can be found.   # noqa: E501

        :param host: The host of this Registry.  # noqa: E501
        :type: str
        """
        if host is not None and len(host) > 255:
            raise ValueError("Invalid value for `host`, length must be less than or equal to `255`")  # noqa: E501

        self._host = host

    @property
    def insecure_skip_verify(self):
        """Gets the insecure_skip_verify of this Registry.  # noqa: E501

        If `true`, Deep Security Smart Check will not verify TLS connections to the registry. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the registry are secured by other means.   # noqa: E501

        :return: The insecure_skip_verify of this Registry.  # noqa: E501
        :rtype: bool
        """
        return self._insecure_skip_verify

    @insecure_skip_verify.setter
    def insecure_skip_verify(self, insecure_skip_verify):
        """Sets the insecure_skip_verify of this Registry.

        If `true`, Deep Security Smart Check will not verify TLS connections to the registry. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the registry are secured by other means.   # noqa: E501

        :param insecure_skip_verify: The insecure_skip_verify of this Registry.  # noqa: E501
        :type: bool
        """

        self._insecure_skip_verify = insecure_skip_verify

    @property
    def root_c_as(self):
        """Gets the root_c_as of this Registry.  # noqa: E501

        (optional, default: `null`) If present, the service will use the provided root CAs as the trusted root CAs for registry requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the service will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :return: The root_c_as of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._root_c_as

    @root_c_as.setter
    def root_c_as(self, root_c_as):
        """Sets the root_c_as of this Registry.

        (optional, default: `null`) If present, the service will use the provided root CAs as the trusted root CAs for registry requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the service will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :param root_c_as: The root_c_as of this Registry.  # noqa: E501
        :type: str
        """
        if root_c_as is not None and len(root_c_as) > 32768:
            raise ValueError("Invalid value for `root_c_as`, length must be less than or equal to `32768`")  # noqa: E501

        self._root_c_as = root_c_as

    @property
    def filter(self):
        """Gets the filter of this Registry.  # noqa: E501


        :return: The filter of this Registry.  # noqa: E501
        :rtype: InlineResponse20010Filter
        """
        return self._filter

    @filter.setter
    def filter(self, filter):
        """Sets the filter of this Registry.


        :param filter: The filter of this Registry.  # noqa: E501
        :type: InlineResponse20010Filter
        """

        self._filter = filter

    @property
    def metrics(self):
        """Gets the metrics of this Registry.  # noqa: E501


        :return: The metrics of this Registry.  # noqa: E501
        :rtype: InlineResponse20010Metrics
        """
        return self._metrics

    @metrics.setter
    def metrics(self, metrics):
        """Sets the metrics of this Registry.


        :param metrics: The metrics of this Registry.  # noqa: E501
        :type: InlineResponse20010Metrics
        """

        self._metrics = metrics

    @property
    def schedule(self):
        """Gets the schedule of this Registry.  # noqa: E501

        If `true`, this registry will be scheduled for daily re-scan.   # noqa: E501

        :return: The schedule of this Registry.  # noqa: E501
        :rtype: bool
        """
        return self._schedule

    @schedule.setter
    def schedule(self, schedule):
        """Sets the schedule of this Registry.

        If `true`, this registry will be scheduled for daily re-scan.   # noqa: E501

        :param schedule: The schedule of this Registry.  # noqa: E501
        :type: bool
        """

        self._schedule = schedule

    @property
    def status(self):
        """Gets the status of this Registry.  # noqa: E501

        Reports the status of the connection from Deep Security Smart Check to the registry. * `pending`: Deep Security Smart Check has not yet attempted to connect to the registry * `ok`: The last connection attempt to the registry was successful. * `failed`: The last connection attempt to the registry failed.   # noqa: E501

        :return: The status of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this Registry.

        Reports the status of the connection from Deep Security Smart Check to the registry. * `pending`: Deep Security Smart Check has not yet attempted to connect to the registry * `ok`: The last connection attempt to the registry was successful. * `failed`: The last connection attempt to the registry failed.   # noqa: E501

        :param status: The status of this Registry.  # noqa: E501
        :type: str
        """
        if status is None:
            raise ValueError("Invalid value for `status`, must not be `None`")  # noqa: E501
        allowed_values = ["pending", "ok", "failed"]  # noqa: E501
        if status not in allowed_values:
            raise ValueError(
                "Invalid value for `status` ({0}), must be one of {1}"  # noqa: E501
                .format(status, allowed_values)
            )

        self._status = status

    @property
    def status_detail(self):
        """Gets the status_detail of this Registry.  # noqa: E501

        Reports additional detail when the status is `failed`.   # noqa: E501

        :return: The status_detail of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._status_detail

    @status_detail.setter
    def status_detail(self, status_detail):
        """Sets the status_detail of this Registry.

        Reports additional detail when the status is `failed`.   # noqa: E501

        :param status_detail: The status_detail of this Registry.  # noqa: E501
        :type: str
        """

        self._status_detail = status_detail

    @property
    def created(self):
        """Gets the created of this Registry.  # noqa: E501

        The time that the registry connection was created.   # noqa: E501

        :return: The created of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this Registry.

        The time that the registry connection was created.   # noqa: E501

        :param created: The created of this Registry.  # noqa: E501
        :type: str
        """
        if created is None:
            raise ValueError("Invalid value for `created`, must not be `None`")  # noqa: E501

        self._created = created

    @property
    def updated(self):
        """Gets the updated of this Registry.  # noqa: E501

        The time that the registry connection was last modified.   # noqa: E501

        :return: The updated of this Registry.  # noqa: E501
        :rtype: str
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this Registry.

        The time that the registry connection was last modified.   # noqa: E501

        :param updated: The updated of this Registry.  # noqa: E501
        :type: str
        """
        if updated is None:
            raise ValueError("Invalid value for `updated`, must not be `None`")  # noqa: E501

        self._updated = updated

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
        if not isinstance(other, Registry):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
