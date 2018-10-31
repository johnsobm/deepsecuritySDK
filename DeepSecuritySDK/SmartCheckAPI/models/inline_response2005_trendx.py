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

from SmartCheckAPI.models.inline_response2005_icrc import InlineResponse2005Icrc  # noqa: F401,E501
from SmartCheckAPI.models.inline_response2005_trendx_related import InlineResponse2005TrendxRelated  # noqa: F401,E501


class InlineResponse2005Trendx(object):
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
        'found': 'InlineResponse2005Icrc',
        'confidence': 'int',
        'related': 'list[InlineResponse2005TrendxRelated]'
    }

    attribute_map = {
        'found': 'found',
        'confidence': 'confidence',
        'related': 'related'
    }

    def __init__(self, found=None, confidence=None, related=None):  # noqa: E501
        """InlineResponse2005Trendx - a model defined in Swagger"""  # noqa: E501

        self._found = None
        self._confidence = None
        self._related = None
        self.discriminator = None

        if found is not None:
            self.found = found
        if confidence is not None:
            self.confidence = confidence
        if related is not None:
            self.related = related

    @property
    def found(self):
        """Gets the found of this InlineResponse2005Trendx.  # noqa: E501


        :return: The found of this InlineResponse2005Trendx.  # noqa: E501
        :rtype: InlineResponse2005Icrc
        """
        return self._found

    @found.setter
    def found(self, found):
        """Sets the found of this InlineResponse2005Trendx.


        :param found: The found of this InlineResponse2005Trendx.  # noqa: E501
        :type: InlineResponse2005Icrc
        """

        self._found = found

    @property
    def confidence(self):
        """Gets the confidence of this InlineResponse2005Trendx.  # noqa: E501


        :return: The confidence of this InlineResponse2005Trendx.  # noqa: E501
        :rtype: int
        """
        return self._confidence

    @confidence.setter
    def confidence(self, confidence):
        """Sets the confidence of this InlineResponse2005Trendx.


        :param confidence: The confidence of this InlineResponse2005Trendx.  # noqa: E501
        :type: int
        """

        self._confidence = confidence

    @property
    def related(self):
        """Gets the related of this InlineResponse2005Trendx.  # noqa: E501


        :return: The related of this InlineResponse2005Trendx.  # noqa: E501
        :rtype: list[InlineResponse2005TrendxRelated]
        """
        return self._related

    @related.setter
    def related(self, related):
        """Sets the related of this InlineResponse2005Trendx.


        :param related: The related of this InlineResponse2005Trendx.  # noqa: E501
        :type: list[InlineResponse2005TrendxRelated]
        """

        self._related = related

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
        if not isinstance(other, InlineResponse2005Trendx):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
