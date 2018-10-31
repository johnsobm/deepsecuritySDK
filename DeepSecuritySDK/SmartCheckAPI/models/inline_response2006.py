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

from SmartCheckAPI.models.inline_response2006_vulnerabilities1 import InlineResponse2006Vulnerabilities1  # noqa: F401,E501


class InlineResponse2006(object):
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
        'vulnerabilities': 'list[InlineResponse2006Vulnerabilities1]',
        'next': 'str'
    }

    attribute_map = {
        'vulnerabilities': 'vulnerabilities',
        'next': 'next'
    }

    def __init__(self, vulnerabilities=None, next=None):  # noqa: E501
        """InlineResponse2006 - a model defined in Swagger"""  # noqa: E501

        self._vulnerabilities = None
        self._next = None
        self.discriminator = None

        if vulnerabilities is not None:
            self.vulnerabilities = vulnerabilities
        if next is not None:
            self.next = next

    @property
    def vulnerabilities(self):
        """Gets the vulnerabilities of this InlineResponse2006.  # noqa: E501


        :return: The vulnerabilities of this InlineResponse2006.  # noqa: E501
        :rtype: list[InlineResponse2006Vulnerabilities1]
        """
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, vulnerabilities):
        """Sets the vulnerabilities of this InlineResponse2006.


        :param vulnerabilities: The vulnerabilities of this InlineResponse2006.  # noqa: E501
        :type: list[InlineResponse2006Vulnerabilities1]
        """

        self._vulnerabilities = vulnerabilities

    @property
    def next(self):
        """Gets the next of this InlineResponse2006.  # noqa: E501

        An encoded value that you can use to retrieve the next set of results for a query. If `next` is not present, then there are no more results available.   # noqa: E501

        :return: The next of this InlineResponse2006.  # noqa: E501
        :rtype: str
        """
        return self._next

    @next.setter
    def next(self, next):
        """Sets the next of this InlineResponse2006.

        An encoded value that you can use to retrieve the next set of results for a query. If `next` is not present, then there are no more results available.   # noqa: E501

        :param next: The next of this InlineResponse2006.  # noqa: E501
        :type: str
        """
        if next is not None and not re.search('^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$', next):  # noqa: E501
            raise ValueError("Invalid value for `next`, must be a follow pattern or equal to `/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/`")  # noqa: E501

        self._next = next

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
        if not isinstance(other, InlineResponse2006):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
