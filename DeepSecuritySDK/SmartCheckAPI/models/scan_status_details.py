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

from SmartCheckAPI.models.inline_response2003_details_results import InlineResponse2003DetailsResults  # noqa: F401,E501


class ScanStatusDetails(object):
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
        'detail': 'str',
        'requested': 'datetime',
        'started': 'datetime',
        'updated': 'datetime',
        'completed': 'datetime',
        'digest': 'str',
        'os': 'str',
        'architecture': 'str',
        'labels': 'dict(str, str)',
        'results': 'list[InlineResponse2003DetailsResults]'
    }

    attribute_map = {
        'detail': 'detail',
        'requested': 'requested',
        'started': 'started',
        'updated': 'updated',
        'completed': 'completed',
        'digest': 'digest',
        'os': 'os',
        'architecture': 'architecture',
        'labels': 'labels',
        'results': 'results'
    }

    def __init__(self, detail=None, requested=None, started=None, updated=None, completed=None, digest=None, os=None, architecture=None, labels=None, results=None):  # noqa: E501
        """ScanStatusDetails - a model defined in Swagger"""  # noqa: E501

        self._detail = None
        self._requested = None
        self._started = None
        self._updated = None
        self._completed = None
        self._digest = None
        self._os = None
        self._architecture = None
        self._labels = None
        self._results = None
        self.discriminator = None

        if detail is not None:
            self.detail = detail
        self.requested = requested
        if started is not None:
            self.started = started
        if updated is not None:
            self.updated = updated
        if completed is not None:
            self.completed = completed
        if digest is not None:
            self.digest = digest
        if os is not None:
            self.os = os
        if architecture is not None:
            self.architecture = architecture
        if labels is not None:
            self.labels = labels
        self.results = results

    @property
    def detail(self):
        """Gets the detail of this ScanStatusDetails.  # noqa: E501

        (optional) More details about the scan status.   # noqa: E501

        :return: The detail of this ScanStatusDetails.  # noqa: E501
        :rtype: str
        """
        return self._detail

    @detail.setter
    def detail(self, detail):
        """Sets the detail of this ScanStatusDetails.

        (optional) More details about the scan status.   # noqa: E501

        :param detail: The detail of this ScanStatusDetails.  # noqa: E501
        :type: str
        """

        self._detail = detail

    @property
    def requested(self):
        """Gets the requested of this ScanStatusDetails.  # noqa: E501

        The time that the scan was requested.   # noqa: E501

        :return: The requested of this ScanStatusDetails.  # noqa: E501
        :rtype: datetime
        """
        return self._requested

    @requested.setter
    def requested(self, requested):
        """Sets the requested of this ScanStatusDetails.

        The time that the scan was requested.   # noqa: E501

        :param requested: The requested of this ScanStatusDetails.  # noqa: E501
        :type: datetime
        """
        if requested is None:
            raise ValueError("Invalid value for `requested`, must not be `None`")  # noqa: E501

        self._requested = requested

    @property
    def started(self):
        """Gets the started of this ScanStatusDetails.  # noqa: E501

        The time that the scan started. This value will not be present if the scan has not yet started.   # noqa: E501

        :return: The started of this ScanStatusDetails.  # noqa: E501
        :rtype: datetime
        """
        return self._started

    @started.setter
    def started(self, started):
        """Sets the started of this ScanStatusDetails.

        The time that the scan started. This value will not be present if the scan has not yet started.   # noqa: E501

        :param started: The started of this ScanStatusDetails.  # noqa: E501
        :type: datetime
        """

        self._started = started

    @property
    def updated(self):
        """Gets the updated of this ScanStatusDetails.  # noqa: E501

        The time that the scan was last updated. This value will not be present if the scan has not yet started.   # noqa: E501

        :return: The updated of this ScanStatusDetails.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this ScanStatusDetails.

        The time that the scan was last updated. This value will not be present if the scan has not yet started.   # noqa: E501

        :param updated: The updated of this ScanStatusDetails.  # noqa: E501
        :type: datetime
        """

        self._updated = updated

    @property
    def completed(self):
        """Gets the completed of this ScanStatusDetails.  # noqa: E501

        The time that the scan completed. This value will not be present if the scan has not yet completed.   # noqa: E501

        :return: The completed of this ScanStatusDetails.  # noqa: E501
        :rtype: datetime
        """
        return self._completed

    @completed.setter
    def completed(self, completed):
        """Sets the completed of this ScanStatusDetails.

        The time that the scan completed. This value will not be present if the scan has not yet completed.   # noqa: E501

        :param completed: The completed of this ScanStatusDetails.  # noqa: E501
        :type: datetime
        """

        self._completed = completed

    @property
    def digest(self):
        """Gets the digest of this ScanStatusDetails.  # noqa: E501

        The image digest for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :return: The digest of this ScanStatusDetails.  # noqa: E501
        :rtype: str
        """
        return self._digest

    @digest.setter
    def digest(self, digest):
        """Sets the digest of this ScanStatusDetails.

        The image digest for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :param digest: The digest of this ScanStatusDetails.  # noqa: E501
        :type: str
        """

        self._digest = digest

    @property
    def os(self):
        """Gets the os of this ScanStatusDetails.  # noqa: E501

        The target operating system for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :return: The os of this ScanStatusDetails.  # noqa: E501
        :rtype: str
        """
        return self._os

    @os.setter
    def os(self, os):
        """Sets the os of this ScanStatusDetails.

        The target operating system for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :param os: The os of this ScanStatusDetails.  # noqa: E501
        :type: str
        """

        self._os = os

    @property
    def architecture(self):
        """Gets the architecture of this ScanStatusDetails.  # noqa: E501

        The target architecture for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :return: The architecture of this ScanStatusDetails.  # noqa: E501
        :rtype: str
        """
        return self._architecture

    @architecture.setter
    def architecture(self, architecture):
        """Sets the architecture of this ScanStatusDetails.

        The target architecture for the scanned image. This value will only be present for Docker scans.   # noqa: E501

        :param architecture: The architecture of this ScanStatusDetails.  # noqa: E501
        :type: str
        """

        self._architecture = architecture

    @property
    def labels(self):
        """Gets the labels of this ScanStatusDetails.  # noqa: E501

        The labels associated with the scanned image. This value will only be present for Docker scans.  # noqa: E501

        :return: The labels of this ScanStatusDetails.  # noqa: E501
        :rtype: dict(str, str)
        """
        return self._labels

    @labels.setter
    def labels(self, labels):
        """Sets the labels of this ScanStatusDetails.

        The labels associated with the scanned image. This value will only be present for Docker scans.  # noqa: E501

        :param labels: The labels of this ScanStatusDetails.  # noqa: E501
        :type: dict(str, str)
        """

        self._labels = labels

    @property
    def results(self):
        """Gets the results of this ScanStatusDetails.  # noqa: E501


        :return: The results of this ScanStatusDetails.  # noqa: E501
        :rtype: list[InlineResponse2003DetailsResults]
        """
        return self._results

    @results.setter
    def results(self, results):
        """Sets the results of this ScanStatusDetails.


        :param results: The results of this ScanStatusDetails.  # noqa: E501
        :type: list[InlineResponse2003DetailsResults]
        """
        if results is None:
            raise ValueError("Invalid value for `results`, must not be `None`")  # noqa: E501

        self._results = results

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
        if not isinstance(other, ScanStatusDetails):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
