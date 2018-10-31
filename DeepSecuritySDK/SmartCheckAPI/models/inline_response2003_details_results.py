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

from SmartCheckAPI.models.inline_response2003_details_findings import InlineResponse2003DetailsFindings  # noqa: F401,E501


class InlineResponse2003DetailsResults(object):
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
        'created_at': 'datetime',
        'created_by': 'str',
        'malware': 'str',
        'vulnerabilities': 'str',
        'findings': 'InlineResponse2003DetailsFindings'
    }

    attribute_map = {
        'id': 'id',
        'created_at': 'createdAt',
        'created_by': 'createdBy',
        'malware': 'malware',
        'vulnerabilities': 'vulnerabilities',
        'findings': 'findings'
    }

    def __init__(self, id=None, created_at=None, created_by=None, malware=None, vulnerabilities=None, findings=None):  # noqa: E501
        """InlineResponse2003DetailsResults - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._created_at = None
        self._created_by = None
        self._malware = None
        self._vulnerabilities = None
        self._findings = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if created_at is not None:
            self.created_at = created_at
        if created_by is not None:
            self.created_by = created_by
        if malware is not None:
            self.malware = malware
        if vulnerabilities is not None:
            self.vulnerabilities = vulnerabilities
        if findings is not None:
            self.findings = findings

    @property
    def id(self):
        """Gets the id of this InlineResponse2003DetailsResults.  # noqa: E501

        A layer identifier. For scans of type `docker`, this will be the layer's `digest` value. This attribute will not be present for scans of type `http`.   # noqa: E501

        :return: The id of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this InlineResponse2003DetailsResults.

        A layer identifier. For scans of type `docker`, this will be the layer's `digest` value. This attribute will not be present for scans of type `http`.   # noqa: E501

        :param id: The id of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def created_at(self):
        """Gets the created_at of this InlineResponse2003DetailsResults.  # noqa: E501

        For scans of Docker images, this attribute will show the time at which the layer was created.   # noqa: E501

        :return: The created_at of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: datetime
        """
        return self._created_at

    @created_at.setter
    def created_at(self, created_at):
        """Sets the created_at of this InlineResponse2003DetailsResults.

        For scans of Docker images, this attribute will show the time at which the layer was created.   # noqa: E501

        :param created_at: The created_at of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: datetime
        """

        self._created_at = created_at

    @property
    def created_by(self):
        """Gets the created_by of this InlineResponse2003DetailsResults.  # noqa: E501

        For scans of Docker images, this attribute will show the Docker daemon command that ran to create this layer. This is not an exact match to the `Dockerfile` line, but will help to provide better context of the results.   # noqa: E501

        :return: The created_by of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: str
        """
        return self._created_by

    @created_by.setter
    def created_by(self, created_by):
        """Sets the created_by of this InlineResponse2003DetailsResults.

        For scans of Docker images, this attribute will show the Docker daemon command that ran to create this layer. This is not an exact match to the `Dockerfile` line, but will help to provide better context of the results.   # noqa: E501

        :param created_by: The created_by of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: str
        """

        self._created_by = created_by

    @property
    def malware(self):
        """Gets the malware of this InlineResponse2003DetailsResults.  # noqa: E501

        If present, a URL pointing to the list of malware that was found. See <a href=\"#listScanLayerMalware\">listScanLayerMalware</a>.   # noqa: E501

        :return: The malware of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: str
        """
        return self._malware

    @malware.setter
    def malware(self, malware):
        """Sets the malware of this InlineResponse2003DetailsResults.

        If present, a URL pointing to the list of malware that was found. See <a href=\"#listScanLayerMalware\">listScanLayerMalware</a>.   # noqa: E501

        :param malware: The malware of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: str
        """

        self._malware = malware

    @property
    def vulnerabilities(self):
        """Gets the vulnerabilities of this InlineResponse2003DetailsResults.  # noqa: E501

        If present, a URL pointing to the list of vulnerabilities that were found. See <a href=\"#listScanLayerVulnerabilities\">listScanLayerVulnerabilities</a>.   # noqa: E501

        :return: The vulnerabilities of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: str
        """
        return self._vulnerabilities

    @vulnerabilities.setter
    def vulnerabilities(self, vulnerabilities):
        """Sets the vulnerabilities of this InlineResponse2003DetailsResults.

        If present, a URL pointing to the list of vulnerabilities that were found. See <a href=\"#listScanLayerVulnerabilities\">listScanLayerVulnerabilities</a>.   # noqa: E501

        :param vulnerabilities: The vulnerabilities of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: str
        """

        self._vulnerabilities = vulnerabilities

    @property
    def findings(self):
        """Gets the findings of this InlineResponse2003DetailsResults.  # noqa: E501


        :return: The findings of this InlineResponse2003DetailsResults.  # noqa: E501
        :rtype: InlineResponse2003DetailsFindings
        """
        return self._findings

    @findings.setter
    def findings(self, findings):
        """Sets the findings of this InlineResponse2003DetailsResults.


        :param findings: The findings of this InlineResponse2003DetailsResults.  # noqa: E501
        :type: InlineResponse2003DetailsFindings
        """

        self._findings = findings

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
        if not isinstance(other, InlineResponse2003DetailsResults):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
