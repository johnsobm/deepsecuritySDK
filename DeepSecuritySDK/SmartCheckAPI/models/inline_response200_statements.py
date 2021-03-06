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


class InlineResponse200Statements(object):
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
        'effect': 'str',
        'actions': 'list[str]'
    }

    attribute_map = {
        'effect': 'effect',
        'actions': 'actions'
    }

    def __init__(self, effect=None, actions=None):  # noqa: E501
        """InlineResponse200Statements - a model defined in Swagger"""  # noqa: E501

        self._effect = None
        self._actions = None
        self.discriminator = None

        if effect is not None:
            self.effect = effect
        if actions is not None:
            self.actions = actions

    @property
    def effect(self):
        """Gets the effect of this InlineResponse200Statements.  # noqa: E501

        The policy effect if the statement matches.   # noqa: E501

        :return: The effect of this InlineResponse200Statements.  # noqa: E501
        :rtype: str
        """
        return self._effect

    @effect.setter
    def effect(self, effect):
        """Sets the effect of this InlineResponse200Statements.

        The policy effect if the statement matches.   # noqa: E501

        :param effect: The effect of this InlineResponse200Statements.  # noqa: E501
        :type: str
        """
        allowed_values = ["allow", "deny"]  # noqa: E501
        if effect not in allowed_values:
            raise ValueError(
                "Invalid value for `effect` ({0}), must be one of {1}"  # noqa: E501
                .format(effect, allowed_values)
            )

        self._effect = effect

    @property
    def actions(self):
        """Gets the actions of this InlineResponse200Statements.  # noqa: E501

        A list of actions. Actions take the form `resourceType:operation` and can have a wildcard in either the `resourceType` or `operation` part. You can also use `*` to match all actions. The required action is listed with each API operation.   # noqa: E501

        :return: The actions of this InlineResponse200Statements.  # noqa: E501
        :rtype: list[str]
        """
        return self._actions

    @actions.setter
    def actions(self, actions):
        """Sets the actions of this InlineResponse200Statements.

        A list of actions. Actions take the form `resourceType:operation` and can have a wildcard in either the `resourceType` or `operation` part. You can also use `*` to match all actions. The required action is listed with each API operation.   # noqa: E501

        :param actions: The actions of this InlineResponse200Statements.  # noqa: E501
        :type: list[str]
        """

        self._actions = actions

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
        if not isinstance(other, InlineResponse200Statements):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
