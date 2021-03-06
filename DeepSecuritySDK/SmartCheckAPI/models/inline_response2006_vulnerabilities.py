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


class InlineResponse2006Vulnerabilities(object):
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
        'description': 'str',
        'fixed_by': 'str',
        'link': 'str',
        'name': 'str',
        'namespace_name': 'str',
        'severity': 'str'
    }

    attribute_map = {
        'description': 'description',
        'fixed_by': 'fixedBy',
        'link': 'link',
        'name': 'name',
        'namespace_name': 'namespaceName',
        'severity': 'severity'
    }

    def __init__(self, description=None, fixed_by=None, link=None, name=None, namespace_name=None, severity=None):  # noqa: E501
        """InlineResponse2006Vulnerabilities - a model defined in Swagger"""  # noqa: E501

        self._description = None
        self._fixed_by = None
        self._link = None
        self._name = None
        self._namespace_name = None
        self._severity = None
        self.discriminator = None

        self.description = description
        if fixed_by is not None:
            self.fixed_by = fixed_by
        if link is not None:
            self.link = link
        self.name = name
        self.namespace_name = namespace_name
        self.severity = severity

    @property
    def description(self):
        """Gets the description of this InlineResponse2006Vulnerabilities.  # noqa: E501

        A description of the known vulnerability in this package.   # noqa: E501

        :return: The description of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this InlineResponse2006Vulnerabilities.

        A description of the known vulnerability in this package.   # noqa: E501

        :param description: The description of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """
        if description is None:
            raise ValueError("Invalid value for `description`, must not be `None`")  # noqa: E501

        self._description = description

    @property
    def fixed_by(self):
        """Gets the fixed_by of this InlineResponse2006Vulnerabilities.  # noqa: E501

        The version of the package where the vulnerability has been resolved.   # noqa: E501

        :return: The fixed_by of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._fixed_by

    @fixed_by.setter
    def fixed_by(self, fixed_by):
        """Sets the fixed_by of this InlineResponse2006Vulnerabilities.

        The version of the package where the vulnerability has been resolved.   # noqa: E501

        :param fixed_by: The fixed_by of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """

        self._fixed_by = fixed_by

    @property
    def link(self):
        """Gets the link of this InlineResponse2006Vulnerabilities.  # noqa: E501

        A link to more information about the vulnerability.   # noqa: E501

        :return: The link of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._link

    @link.setter
    def link(self, link):
        """Sets the link of this InlineResponse2006Vulnerabilities.

        A link to more information about the vulnerability.   # noqa: E501

        :param link: The link of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """

        self._link = link

    @property
    def name(self):
        """Gets the name of this InlineResponse2006Vulnerabilities.  # noqa: E501

        The name of the vulnerability.   # noqa: E501

        :return: The name of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this InlineResponse2006Vulnerabilities.

        The name of the vulnerability.   # noqa: E501

        :param name: The name of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501

        self._name = name

    @property
    def namespace_name(self):
        """Gets the namespace_name of this InlineResponse2006Vulnerabilities.  # noqa: E501

        The namespace that the package `name` is unique within.   # noqa: E501

        :return: The namespace_name of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._namespace_name

    @namespace_name.setter
    def namespace_name(self, namespace_name):
        """Sets the namespace_name of this InlineResponse2006Vulnerabilities.

        The namespace that the package `name` is unique within.   # noqa: E501

        :param namespace_name: The namespace_name of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """
        if namespace_name is None:
            raise ValueError("Invalid value for `namespace_name`, must not be `None`")  # noqa: E501

        self._namespace_name = namespace_name

    @property
    def severity(self):
        """Gets the severity of this InlineResponse2006Vulnerabilities.  # noqa: E501

        The severity assigned to the vulnerability: * Defcon1: is a `Critical` problem which has been manually highlighted by the team. It requires immediate attention. * Critical: a world-burning problem, exploitable for nearly all people in a default installation of Linux. Includes remote root privilege escalations, or massive data loss. * High: a real problem, exploitable for many people in a default installation. Includes serious remote denial of services, local root privilege escalations, or data loss. * Medium: a real security problem, and is exploitable for many people. Includes network daemon denial of service attacks, cross-site scripting, and gaining user privileges. Updates should be made soon for this priority of issue. * Low: a security problem, but is hard to exploit due to environment, requires a user-assisted attack, a small install base, or does very little damage. These tend to be included in security updates only when higher-priority issues require an upgrade, or if many low-priority issues have built up. * Negligible: is technically a security problem, but is only theoretical in nature, requires a very special situation, has almost no install base, or does no real damage. These tend not to get backported from upstreams, and will likely not be included in security updates unless there is an easy fix and some other issue causes an update.   # noqa: E501

        :return: The severity of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :rtype: str
        """
        return self._severity

    @severity.setter
    def severity(self, severity):
        """Sets the severity of this InlineResponse2006Vulnerabilities.

        The severity assigned to the vulnerability: * Defcon1: is a `Critical` problem which has been manually highlighted by the team. It requires immediate attention. * Critical: a world-burning problem, exploitable for nearly all people in a default installation of Linux. Includes remote root privilege escalations, or massive data loss. * High: a real problem, exploitable for many people in a default installation. Includes serious remote denial of services, local root privilege escalations, or data loss. * Medium: a real security problem, and is exploitable for many people. Includes network daemon denial of service attacks, cross-site scripting, and gaining user privileges. Updates should be made soon for this priority of issue. * Low: a security problem, but is hard to exploit due to environment, requires a user-assisted attack, a small install base, or does very little damage. These tend to be included in security updates only when higher-priority issues require an upgrade, or if many low-priority issues have built up. * Negligible: is technically a security problem, but is only theoretical in nature, requires a very special situation, has almost no install base, or does no real damage. These tend not to get backported from upstreams, and will likely not be included in security updates unless there is an easy fix and some other issue causes an update.   # noqa: E501

        :param severity: The severity of this InlineResponse2006Vulnerabilities.  # noqa: E501
        :type: str
        """
        if severity is None:
            raise ValueError("Invalid value for `severity`, must not be `None`")  # noqa: E501
        allowed_values = ["Defcon1", "Critical", "High", "Medium", "Low", "Negligible", "Unknown"]  # noqa: E501
        if severity not in allowed_values:
            raise ValueError(
                "Invalid value for `severity` ({0}), must be one of {1}"  # noqa: E501
                .format(severity, allowed_values)
            )

        self._severity = severity

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
        if not isinstance(other, InlineResponse2006Vulnerabilities):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
