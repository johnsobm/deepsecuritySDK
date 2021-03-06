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

from SmartCheckAPI.models.inline_response2007_headers import InlineResponse2007Headers  # noqa: F401,E501


class InlineResponse2007Webhooks(object):
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
        'hook_url': 'str',
        'headers': 'list[InlineResponse2007Headers]',
        'insecure_skip_verify': 'bool',
        'root_c_as': 'str',
        'active': 'bool',
        'events': 'list[str]',
        'created': 'datetime',
        'updated': 'datetime'
    }

    attribute_map = {
        'id': 'id',
        'href': 'href',
        'name': 'name',
        'hook_url': 'hookURL',
        'headers': 'headers',
        'insecure_skip_verify': 'insecureSkipVerify',
        'root_c_as': 'rootCAs',
        'active': 'active',
        'events': 'events',
        'created': 'created',
        'updated': 'updated'
    }

    def __init__(self, id=None, href=None, name=None, hook_url=None, headers=None, insecure_skip_verify=None, root_c_as=None, active=None, events=None, created=None, updated=None):  # noqa: E501
        """InlineResponse2007Webhooks - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._href = None
        self._name = None
        self._hook_url = None
        self._headers = None
        self._insecure_skip_verify = None
        self._root_c_as = None
        self._active = None
        self._events = None
        self._created = None
        self._updated = None
        self.discriminator = None

        self.id = id
        self.href = href
        self.name = name
        self.hook_url = hook_url
        self.headers = headers
        if insecure_skip_verify is not None:
            self.insecure_skip_verify = insecure_skip_verify
        if root_c_as is not None:
            self.root_c_as = root_c_as
        self.active = active
        self.events = events
        self.created = created
        if updated is not None:
            self.updated = updated

    @property
    def id(self):
        """Gets the id of this InlineResponse2007Webhooks.  # noqa: E501

        (optional) If you provide a web hook ID, the scanner will check whether it has already received another request from you with the same ID. If it has, the scanner will return `409 Conflict`. If you don't provide a web hook ID, the scanner will create one for you.   # noqa: E501

        :return: The id of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this InlineResponse2007Webhooks.

        (optional) If you provide a web hook ID, the scanner will check whether it has already received another request from you with the same ID. If it has, the scanner will return `409 Conflict`. If you don't provide a web hook ID, the scanner will create one for you.   # noqa: E501

        :param id: The id of this InlineResponse2007Webhooks.  # noqa: E501
        :type: str
        """
        if id is None:
            raise ValueError("Invalid value for `id`, must not be `None`")  # noqa: E501

        self._id = id

    @property
    def href(self):
        """Gets the href of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The href of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: str
        """
        return self._href

    @href.setter
    def href(self, href):
        """Sets the href of this InlineResponse2007Webhooks.


        :param href: The href of this InlineResponse2007Webhooks.  # noqa: E501
        :type: str
        """
        if href is None:
            raise ValueError("Invalid value for `href`, must not be `None`")  # noqa: E501

        self._href = href

    @property
    def name(self):
        """Gets the name of this InlineResponse2007Webhooks.  # noqa: E501

        (optional) A descriptive name for the web hook.   # noqa: E501

        :return: The name of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this InlineResponse2007Webhooks.

        (optional) A descriptive name for the web hook.   # noqa: E501

        :param name: The name of this InlineResponse2007Webhooks.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501
        if name is not None and len(name) > 64:
            raise ValueError("Invalid value for `name`, length must be less than or equal to `64`")  # noqa: E501

        self._name = name

    @property
    def hook_url(self):
        """Gets the hook_url of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The hook_url of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: str
        """
        return self._hook_url

    @hook_url.setter
    def hook_url(self, hook_url):
        """Sets the hook_url of this InlineResponse2007Webhooks.


        :param hook_url: The hook_url of this InlineResponse2007Webhooks.  # noqa: E501
        :type: str
        """
        if hook_url is None:
            raise ValueError("Invalid value for `hook_url`, must not be `None`")  # noqa: E501
        if hook_url is not None and len(hook_url) > 255:
            raise ValueError("Invalid value for `hook_url`, length must be less than or equal to `255`")  # noqa: E501

        self._hook_url = hook_url

    @property
    def headers(self):
        """Gets the headers of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The headers of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: list[InlineResponse2007Headers]
        """
        return self._headers

    @headers.setter
    def headers(self, headers):
        """Sets the headers of this InlineResponse2007Webhooks.


        :param headers: The headers of this InlineResponse2007Webhooks.  # noqa: E501
        :type: list[InlineResponse2007Headers]
        """
        if headers is None:
            raise ValueError("Invalid value for `headers`, must not be `None`")  # noqa: E501

        self._headers = headers

    @property
    def insecure_skip_verify(self):
        """Gets the insecure_skip_verify of this InlineResponse2007Webhooks.  # noqa: E501

        (optional, default: `false`) If `true`, the web hook will not verify TLS connections to the web hook URL. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the hook URL are secured by other means.   # noqa: E501

        :return: The insecure_skip_verify of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: bool
        """
        return self._insecure_skip_verify

    @insecure_skip_verify.setter
    def insecure_skip_verify(self, insecure_skip_verify):
        """Sets the insecure_skip_verify of this InlineResponse2007Webhooks.

        (optional, default: `false`) If `true`, the web hook will not verify TLS connections to the web hook URL. Use this only in controlled environments where you know that connections between the Deep Security Smart Check scanner and the hook URL are secured by other means.   # noqa: E501

        :param insecure_skip_verify: The insecure_skip_verify of this InlineResponse2007Webhooks.  # noqa: E501
        :type: bool
        """

        self._insecure_skip_verify = insecure_skip_verify

    @property
    def root_c_as(self):
        """Gets the root_c_as of this InlineResponse2007Webhooks.  # noqa: E501

        (optional, default: `null`) If present, the web hook will use the provided root CAs as the trusted root CAs for HTTPS web hook requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the web hook will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :return: The root_c_as of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: str
        """
        return self._root_c_as

    @root_c_as.setter
    def root_c_as(self, root_c_as):
        """Sets the root_c_as of this InlineResponse2007Webhooks.

        (optional, default: `null`) If present, the web hook will use the provided root CAs as the trusted root CAs for HTTPS web hook requests. The value should be a base-64 encoded list of PEM-encoded certificates. If not present, the web hook will use a set of built-in trusted root CAs. If `insecureSkipVerify` is set to `true`, then the root CAs are not checked.   # noqa: E501

        :param root_c_as: The root_c_as of this InlineResponse2007Webhooks.  # noqa: E501
        :type: str
        """
        if root_c_as is not None and len(root_c_as) > 32768:
            raise ValueError("Invalid value for `root_c_as`, length must be less than or equal to `32768`")  # noqa: E501

        self._root_c_as = root_c_as

    @property
    def active(self):
        """Gets the active of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The active of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: bool
        """
        return self._active

    @active.setter
    def active(self, active):
        """Sets the active of this InlineResponse2007Webhooks.


        :param active: The active of this InlineResponse2007Webhooks.  # noqa: E501
        :type: bool
        """
        if active is None:
            raise ValueError("Invalid value for `active`, must not be `None`")  # noqa: E501

        self._active = active

    @property
    def events(self):
        """Gets the events of this InlineResponse2007Webhooks.  # noqa: E501

        (optional, default: `[\"*\"]`) If present, this is a list of event types that will be checked before calling the web hook. If the event type matches one of the elements of the list, the web hook will be called. If the list is empty, *all* events will match.   # noqa: E501

        :return: The events of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: list[str]
        """
        return self._events

    @events.setter
    def events(self, events):
        """Sets the events of this InlineResponse2007Webhooks.

        (optional, default: `[\"*\"]`) If present, this is a list of event types that will be checked before calling the web hook. If the event type matches one of the elements of the list, the web hook will be called. If the list is empty, *all* events will match.   # noqa: E501

        :param events: The events of this InlineResponse2007Webhooks.  # noqa: E501
        :type: list[str]
        """
        if events is None:
            raise ValueError("Invalid value for `events`, must not be `None`")  # noqa: E501
        allowed_values = ["scan-requested", "scan-started", "scan-completed", "*"]  # noqa: E501
        if not set(events).issubset(set(allowed_values)):
            raise ValueError(
                "Invalid values for `events` [{0}], must be a subset of [{1}]"  # noqa: E501
                .format(", ".join(map(str, set(events) - set(allowed_values))),  # noqa: E501
                        ", ".join(map(str, allowed_values)))
            )

        self._events = events

    @property
    def created(self):
        """Gets the created of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The created of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: datetime
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this InlineResponse2007Webhooks.


        :param created: The created of this InlineResponse2007Webhooks.  # noqa: E501
        :type: datetime
        """
        if created is None:
            raise ValueError("Invalid value for `created`, must not be `None`")  # noqa: E501

        self._created = created

    @property
    def updated(self):
        """Gets the updated of this InlineResponse2007Webhooks.  # noqa: E501


        :return: The updated of this InlineResponse2007Webhooks.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this InlineResponse2007Webhooks.


        :param updated: The updated of this InlineResponse2007Webhooks.  # noqa: E501
        :type: datetime
        """

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
        if not isinstance(other, InlineResponse2007Webhooks):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
