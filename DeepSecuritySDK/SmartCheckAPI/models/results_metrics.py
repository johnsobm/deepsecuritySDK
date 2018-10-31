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

from SmartCheckAPI.models.inline_response2003_details_findings_scanners import InlineResponse2003DetailsFindingsScanners  # noqa: F401,E501
from SmartCheckAPI.models.inline_response2003_details_findings_vulnerabilities import InlineResponse2003DetailsFindingsVulnerabilities  # noqa: F401,E501


class ResultsMetrics(object):
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
        'scanners': 'InlineResponse2003DetailsFindingsScanners',
        'malware': 'int',
        'vulnerabilities': 'InlineResponse2003DetailsFindingsVulnerabilities'
    }

    attribute_map = {
        'scanners': 'scanners',
        'malware': 'malware',
        'vulnerabilities': 'vulnerabilities'
    }

    def __init__(self, scanners=None, malware=None, vulnerabilities=None):  # noqa: E501
        """ResultsMetrics - a model defined in Swagger"""  # noqa: E501

        self._scanners = None
        self._malware = None
        self._vulnerabilities = None
        self.discriminator = None

        if scanners is not None:
            self.scanners = scanners
        if malware is not None:
            self.malware = malware
        if vulnerabilities is not None:
            self.vulnerabilities = vulnerabilities

    @property
    def scanners(self):
        """Gets the scanners of this ResultsMetrics.  # noqa: E501


        :return: The scanners of this ResultsMetrics.  # noqa: E501
        :rtype: InlineResponse2003DetailsFindingsScanners
        """
        return self._scanners

    @scanners.setter
    def scanners(self, scanners):
        """Sets the scanners of this ResultsMetrics.


        :param scanners: The scanners of this ResultsMetrics.  # noqa: E501
        :type: InlineResponse2003DetailsFindingsScanners
        """

        self._scanners = scanners

    @property
    def malware(self):
        """Gets the malware of this ResultsMetrics.  # noqa: E501

        The number of malware items that were found. high:   # noqa: E501

        :return: The malware of this ResultsMetrics.  # noqa: E501
        :rtype: int
        """
        return self._malware

    @malware.setter
    def malware(self, malware):
        """Sets the malware of this ResultsMetrics.

        The number of malware items that were found. high:   # noqa: E501

        :param malware: The malware of this ResultsMetrics.  # noqa: E501
        :type: int
        """

        self._malware = malware

    @property
    def vulnerabilities(self):
        """Gets the vulnerabilities of this ResultsMetrics.  # noqa: E501


        :return: The vulnerabilities of this ResultsMetrics.  # noqa: E501
        :rtype: InlineResponse2003DetailsFindingsVulnerabilities
        """
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, vulnerabilities):
        """Sets the vulnerabilities of this ResultsMetrics.


        :param vulnerabilities: The vulnerabilities of this ResultsMetrics.  # noqa: E501
        :type: InlineResponse2003DetailsFindingsVulnerabilities
        """

        self._vulnerabilities = vulnerabilities

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
        if not isinstance(other, ResultsMetrics):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other