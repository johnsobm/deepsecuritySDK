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

from SmartCheckAPI.models.inline_response20010_metrics_history1d import InlineResponse20010MetricsHistory1d  # noqa: F401,E501
from SmartCheckAPI.models.inline_response20010_metrics_history1w import InlineResponse20010MetricsHistory1w  # noqa: F401,E501


class InlineResponse20010MetricsHistory(object):
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
        '_1d': 'InlineResponse20010MetricsHistory1d',
        '_1w': 'InlineResponse20010MetricsHistory1w'
    }

    attribute_map = {
        '_1d': '1d',
        '_1w': '1w'
    }

    def __init__(self, _1d=None, _1w=None):  # noqa: E501
        """InlineResponse20010MetricsHistory - a model defined in Swagger"""  # noqa: E501

        self.__1d = None
        self.__1w = None
        self.discriminator = None

        if _1d is not None:
            self._1d = _1d
        if _1w is not None:
            self._1w = _1w

    @property
    def _1d(self):
        """Gets the _1d of this InlineResponse20010MetricsHistory.  # noqa: E501


        :return: The _1d of this InlineResponse20010MetricsHistory.  # noqa: E501
        :rtype: InlineResponse20010MetricsHistory1d
        """
        return self.__1d

    @_1d.setter
    def _1d(self, _1d):
        """Sets the _1d of this InlineResponse20010MetricsHistory.


        :param _1d: The _1d of this InlineResponse20010MetricsHistory.  # noqa: E501
        :type: InlineResponse20010MetricsHistory1d
        """

        self.__1d = _1d

    @property
    def _1w(self):
        """Gets the _1w of this InlineResponse20010MetricsHistory.  # noqa: E501


        :return: The _1w of this InlineResponse20010MetricsHistory.  # noqa: E501
        :rtype: InlineResponse20010MetricsHistory1w
        """
        return self.__1w

    @_1w.setter
    def _1w(self, _1w):
        """Sets the _1w of this InlineResponse20010MetricsHistory.


        :param _1w: The _1w of this InlineResponse20010MetricsHistory.  # noqa: E501
        :type: InlineResponse20010MetricsHistory1w
        """

        self.__1w = _1w

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
        if not isinstance(other, InlineResponse20010MetricsHistory):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other