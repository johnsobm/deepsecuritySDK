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


class IntegrityMonitoringAssignments(object):
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
        'assigned_rule_i_ds': 'list[int]',
        'recommendation_scan_status': 'str',
        'last_recommendation_scan_date': 'int',
        'recommended_to_assign_rule_i_ds': 'list[int]',
        'recommended_to_unassign_rule_i_ds': 'list[int]'
    }

    attribute_map = {
        'assigned_rule_i_ds': 'assignedRuleIDs',
        'recommendation_scan_status': 'recommendationScanStatus',
        'last_recommendation_scan_date': 'lastRecommendationScanDate',
        'recommended_to_assign_rule_i_ds': 'recommendedToAssignRuleIDs',
        'recommended_to_unassign_rule_i_ds': 'recommendedToUnassignRuleIDs'
    }

    def __init__(self, assigned_rule_i_ds=None, recommendation_scan_status=None, last_recommendation_scan_date=None, recommended_to_assign_rule_i_ds=None, recommended_to_unassign_rule_i_ds=None):  # noqa: E501
        """IntegrityMonitoringAssignments - a model defined in Swagger"""  # noqa: E501

        self._assigned_rule_i_ds = None
        self._recommendation_scan_status = None
        self._last_recommendation_scan_date = None
        self._recommended_to_assign_rule_i_ds = None
        self._recommended_to_unassign_rule_i_ds = None
        self.discriminator = None

        if assigned_rule_i_ds is not None:
            self.assigned_rule_i_ds = assigned_rule_i_ds
        if recommendation_scan_status is not None:
            self.recommendation_scan_status = recommendation_scan_status
        if last_recommendation_scan_date is not None:
            self.last_recommendation_scan_date = last_recommendation_scan_date
        if recommended_to_assign_rule_i_ds is not None:
            self.recommended_to_assign_rule_i_ds = recommended_to_assign_rule_i_ds
        if recommended_to_unassign_rule_i_ds is not None:
            self.recommended_to_unassign_rule_i_ds = recommended_to_unassign_rule_i_ds

    @property
    def assigned_rule_i_ds(self):
        """Gets the assigned_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501

        IDs of IntegrityMonitoringRules assigned to the computer or policy.  # noqa: E501

        :return: The assigned_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._assigned_rule_i_ds

    @assigned_rule_i_ds.setter
    def assigned_rule_i_ds(self, assigned_rule_i_ds):
        """Sets the assigned_rule_i_ds of this IntegrityMonitoringAssignments.

        IDs of IntegrityMonitoringRules assigned to the computer or policy.  # noqa: E501

        :param assigned_rule_i_ds: The assigned_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :type: list[int]
        """

        self._assigned_rule_i_ds = assigned_rule_i_ds

    @property
    def recommendation_scan_status(self):
        """Gets the recommendation_scan_status of this IntegrityMonitoringAssignments.  # noqa: E501

        Status of the last recommendation scan done on a computer or policy.  # noqa: E501

        :return: The recommendation_scan_status of this IntegrityMonitoringAssignments.  # noqa: E501
        :rtype: str
        """
        return self._recommendation_scan_status

    @recommendation_scan_status.setter
    def recommendation_scan_status(self, recommendation_scan_status):
        """Sets the recommendation_scan_status of this IntegrityMonitoringAssignments.

        Status of the last recommendation scan done on a computer or policy.  # noqa: E501

        :param recommendation_scan_status: The recommendation_scan_status of this IntegrityMonitoringAssignments.  # noqa: E501
        :type: str
        """
        allowed_values = ["none", "valid", "out-of-date", "unknown"]  # noqa: E501
        if recommendation_scan_status not in allowed_values:
            raise ValueError(
                "Invalid value for `recommendation_scan_status` ({0}), must be one of {1}"  # noqa: E501
                .format(recommendation_scan_status, allowed_values)
            )

        self._recommendation_scan_status = recommendation_scan_status

    @property
    def last_recommendation_scan_date(self):
        """Gets the last_recommendation_scan_date of this IntegrityMonitoringAssignments.  # noqa: E501

        Timestamp of the last recommendation scan date, in milliseconds since epoch.  # noqa: E501

        :return: The last_recommendation_scan_date of this IntegrityMonitoringAssignments.  # noqa: E501
        :rtype: int
        """
        return self._last_recommendation_scan_date

    @last_recommendation_scan_date.setter
    def last_recommendation_scan_date(self, last_recommendation_scan_date):
        """Sets the last_recommendation_scan_date of this IntegrityMonitoringAssignments.

        Timestamp of the last recommendation scan date, in milliseconds since epoch.  # noqa: E501

        :param last_recommendation_scan_date: The last_recommendation_scan_date of this IntegrityMonitoringAssignments.  # noqa: E501
        :type: int
        """

        self._last_recommendation_scan_date = last_recommendation_scan_date

    @property
    def recommended_to_assign_rule_i_ds(self):
        """Gets the recommended_to_assign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501

        IntegrityMonitoringRules separated by commas, that were recommended to be assigned to the computer or policy by a recommendation scan.  # noqa: E501

        :return: The recommended_to_assign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._recommended_to_assign_rule_i_ds

    @recommended_to_assign_rule_i_ds.setter
    def recommended_to_assign_rule_i_ds(self, recommended_to_assign_rule_i_ds):
        """Sets the recommended_to_assign_rule_i_ds of this IntegrityMonitoringAssignments.

        IntegrityMonitoringRules separated by commas, that were recommended to be assigned to the computer or policy by a recommendation scan.  # noqa: E501

        :param recommended_to_assign_rule_i_ds: The recommended_to_assign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :type: list[int]
        """

        self._recommended_to_assign_rule_i_ds = recommended_to_assign_rule_i_ds

    @property
    def recommended_to_unassign_rule_i_ds(self):
        """Gets the recommended_to_unassign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501

        IntegrityMonitoringRules, separated by commas, that were recommended to be unassigned from the computer or policy by a recommendation scan.  # noqa: E501

        :return: The recommended_to_unassign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._recommended_to_unassign_rule_i_ds

    @recommended_to_unassign_rule_i_ds.setter
    def recommended_to_unassign_rule_i_ds(self, recommended_to_unassign_rule_i_ds):
        """Sets the recommended_to_unassign_rule_i_ds of this IntegrityMonitoringAssignments.

        IntegrityMonitoringRules, separated by commas, that were recommended to be unassigned from the computer or policy by a recommendation scan.  # noqa: E501

        :param recommended_to_unassign_rule_i_ds: The recommended_to_unassign_rule_i_ds of this IntegrityMonitoringAssignments.  # noqa: E501
        :type: list[int]
        """

        self._recommended_to_unassign_rule_i_ds = recommended_to_unassign_rule_i_ds

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
        if not isinstance(other, IntegrityMonitoringAssignments):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
