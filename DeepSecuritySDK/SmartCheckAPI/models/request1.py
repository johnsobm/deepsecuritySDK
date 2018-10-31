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

from SmartCheckAPI.models.inline_response200_policies import InlineResponse200Policies  # noqa: F401,E501


class Request1(object):
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
        'policies': 'list[InlineResponse200Policies]'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'policies': 'policies'
    }

    def __init__(self, name=None, description=None, policies=None):  # noqa: E501
        """Request1 - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._policies = None
        self.discriminator = None

        self.name = name
        if description is not None:
            self.description = description
        self.policies = policies

    @property
    def name(self):
        """Gets the name of this Request1.  # noqa: E501

        A name for the role.   # noqa: E501

        :return: The name of this Request1.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this Request1.

        A name for the role.   # noqa: E501

        :param name: The name of this Request1.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501
        if name is not None and len(name) > 128:
            raise ValueError("Invalid value for `name`, length must be less than or equal to `128`")  # noqa: E501

        self._name = name

    @property
    def description(self):
        """Gets the description of this Request1.  # noqa: E501

        A description for the role.   # noqa: E501

        :return: The description of this Request1.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this Request1.

        A description for the role.   # noqa: E501

        :param description: The description of this Request1.  # noqa: E501
        :type: str
        """
        if description is not None and len(description) > 2048:
            raise ValueError("Invalid value for `description`, length must be less than or equal to `2048`")  # noqa: E501

        self._description = description

    @property
    def policies(self):
        """Gets the policies of this Request1.  # noqa: E501

        A list of policies for the role. The total size of the policy list must be less than 32768 bytes.   # noqa: E501

        :return: The policies of this Request1.  # noqa: E501
        :rtype: list[InlineResponse200Policies]
        """
        return self._policies

    @policies.setter
    def policies(self, policies):
        """Sets the policies of this Request1.

        A list of policies for the role. The total size of the policy list must be less than 32768 bytes.   # noqa: E501

        :param policies: The policies of this Request1.  # noqa: E501
        :type: list[InlineResponse200Policies]
        """
        if policies is None:
            raise ValueError("Invalid value for `policies`, must not be `None`")  # noqa: E501

        self._policies = policies

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
        if not isinstance(other, Request1):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
