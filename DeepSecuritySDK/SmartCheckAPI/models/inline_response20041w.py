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


class InlineResponse20041w(object):
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
        'scans': 'int'
    }

    attribute_map = {
        'scans': 'scans'
    }

    def __init__(self, scans=None):  # noqa: E501
        """InlineResponse20041w - a model defined in Swagger"""  # noqa: E501

        self._scans = None
        self.discriminator = None

        if scans is not None:
            self.scans = scans

    @property
    def scans(self):
        """Gets the scans of this InlineResponse20041w.  # noqa: E501

        The number of scans performed in the time period.   # noqa: E501

        :return: The scans of this InlineResponse20041w.  # noqa: E501
        :rtype: int
        """
        return self._scans

    @scans.setter
    def scans(self, scans):
        """Sets the scans of this InlineResponse20041w.

        The number of scans performed in the time period.   # noqa: E501

        :param scans: The scans of this InlineResponse20041w.  # noqa: E501
        :type: int
        """

        self._scans = scans

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
        if not isinstance(other, InlineResponse20041w):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other