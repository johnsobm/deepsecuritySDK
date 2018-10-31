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


class NoConnectorVirtualMachineSummary(object):
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
        'account_id': 'str',
        'directory_id': 'str',
        'user_name': 'str',
        'instance_id': 'str',
        'region': 'str'
    }

    attribute_map = {
        'account_id': 'accountID',
        'directory_id': 'directoryID',
        'user_name': 'userName',
        'instance_id': 'instanceID',
        'region': 'region'
    }

    def __init__(self, account_id=None, directory_id=None, user_name=None, instance_id=None, region=None):  # noqa: E501
        """NoConnectorVirtualMachineSummary - a model defined in Swagger"""  # noqa: E501

        self._account_id = None
        self._directory_id = None
        self._user_name = None
        self._instance_id = None
        self._region = None
        self.discriminator = None

        if account_id is not None:
            self.account_id = account_id
        if directory_id is not None:
            self.directory_id = directory_id
        if user_name is not None:
            self.user_name = user_name
        if instance_id is not None:
            self.instance_id = instance_id
        if region is not None:
            self.region = region

    @property
    def account_id(self):
        """Gets the account_id of this NoConnectorVirtualMachineSummary.  # noqa: E501

        Agent-reported account ID.  # noqa: E501

        :return: The account_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._account_id

    @account_id.setter
    def account_id(self, account_id):
        """Sets the account_id of this NoConnectorVirtualMachineSummary.

        Agent-reported account ID.  # noqa: E501

        :param account_id: The account_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._account_id = account_id

    @property
    def directory_id(self):
        """Gets the directory_id of this NoConnectorVirtualMachineSummary.  # noqa: E501

        Agent-reported directory ID.  # noqa: E501

        :return: The directory_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._directory_id

    @directory_id.setter
    def directory_id(self, directory_id):
        """Sets the directory_id of this NoConnectorVirtualMachineSummary.

        Agent-reported directory ID.  # noqa: E501

        :param directory_id: The directory_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._directory_id = directory_id

    @property
    def user_name(self):
        """Gets the user_name of this NoConnectorVirtualMachineSummary.  # noqa: E501

        Agent-reported user ID.  # noqa: E501

        :return: The user_name of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._user_name

    @user_name.setter
    def user_name(self, user_name):
        """Sets the user_name of this NoConnectorVirtualMachineSummary.

        Agent-reported user ID.  # noqa: E501

        :param user_name: The user_name of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._user_name = user_name

    @property
    def instance_id(self):
        """Gets the instance_id of this NoConnectorVirtualMachineSummary.  # noqa: E501

        Agent-reported instance ID.  # noqa: E501

        :return: The instance_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._instance_id

    @instance_id.setter
    def instance_id(self, instance_id):
        """Sets the instance_id of this NoConnectorVirtualMachineSummary.

        Agent-reported instance ID.  # noqa: E501

        :param instance_id: The instance_id of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._instance_id = instance_id

    @property
    def region(self):
        """Gets the region of this NoConnectorVirtualMachineSummary.  # noqa: E501

        Agent-reported region.  # noqa: E501

        :return: The region of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :rtype: str
        """
        return self._region

    @region.setter
    def region(self, region):
        """Sets the region of this NoConnectorVirtualMachineSummary.

        Agent-reported region.  # noqa: E501

        :param region: The region of this NoConnectorVirtualMachineSummary.  # noqa: E501
        :type: str
        """

        self._region = region

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
        if not isinstance(other, NoConnectorVirtualMachineSummary):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
