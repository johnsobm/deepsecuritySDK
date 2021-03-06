# coding: utf-8

"""
    Trend Micro Deep Security API

    Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 11.2.225
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class IntegrityMonitoringComputerExtension(object):
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
        'state': 'str',
        'rule_i_ds': 'list[int]'
    }

    attribute_map = {
        'state': 'state',
        'rule_i_ds': 'ruleIDs'
    }

    def __init__(self, state=None, rule_i_ds=None):  # noqa: E501
        """IntegrityMonitoringComputerExtension - a model defined in Swagger"""  # noqa: E501

        self._state = None
        self._rule_i_ds = None
        self.discriminator = None

        if state is not None:
            self.state = state
        if rule_i_ds is not None:
            self.rule_i_ds = rule_i_ds

    @property
    def state(self):
        """Gets the state of this IntegrityMonitoringComputerExtension.  # noqa: E501

        Module running state.  # noqa: E501

        :return: The state of this IntegrityMonitoringComputerExtension.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this IntegrityMonitoringComputerExtension.

        Module running state.  # noqa: E501

        :param state: The state of this IntegrityMonitoringComputerExtension.  # noqa: E501
        :type: str
        """
        allowed_values = ["real-time", "on", "off"]  # noqa: E501
        if state not in allowed_values:
            raise ValueError(
                "Invalid value for `state` ({0}), must be one of {1}"  # noqa: E501
                .format(state, allowed_values)
            )

        self._state = state

    @property
    def rule_i_ds(self):
        """Gets the rule_i_ds of this IntegrityMonitoringComputerExtension.  # noqa: E501

        IDs of the assigned Integrity Monitoring rules.  # noqa: E501

        :return: The rule_i_ds of this IntegrityMonitoringComputerExtension.  # noqa: E501
        :rtype: list[int]
        """
        return self._rule_i_ds

    @rule_i_ds.setter
    def rule_i_ds(self, rule_i_ds):
        """Sets the rule_i_ds of this IntegrityMonitoringComputerExtension.

        IDs of the assigned Integrity Monitoring rules.  # noqa: E501

        :param rule_i_ds: The rule_i_ds of this IntegrityMonitoringComputerExtension.  # noqa: E501
        :type: list[int]
        """

        self._rule_i_ds = rule_i_ds

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
        if not isinstance(other, IntegrityMonitoringComputerExtension):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
