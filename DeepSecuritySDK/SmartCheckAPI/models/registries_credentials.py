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

from SmartCheckAPI.models.scans_source_credentials_aws import ScansSourceCredentialsAws  # noqa: F401,E501


class RegistriesCredentials(object):
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
        'username': 'str',
        'password': 'str',
        'aws': 'ScansSourceCredentialsAws'
    }

    attribute_map = {
        'username': 'username',
        'password': 'password',
        'aws': 'aws'
    }

    def __init__(self, username=None, password=None, aws=None):  # noqa: E501
        """RegistriesCredentials - a model defined in Swagger"""  # noqa: E501

        self._username = None
        self._password = None
        self._aws = None
        self.discriminator = None

        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if aws is not None:
            self.aws = aws

    @property
    def username(self):
        """Gets the username of this RegistriesCredentials.  # noqa: E501

        (optional) Use this if your source requires requests to be authorized using basic username + password authentication. Requests will include an `Authorization: Basic {encoded username + password}` header.   # noqa: E501

        :return: The username of this RegistriesCredentials.  # noqa: E501
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """Sets the username of this RegistriesCredentials.

        (optional) Use this if your source requires requests to be authorized using basic username + password authentication. Requests will include an `Authorization: Basic {encoded username + password}` header.   # noqa: E501

        :param username: The username of this RegistriesCredentials.  # noqa: E501
        :type: str
        """
        if username is not None and len(username) > 64:
            raise ValueError("Invalid value for `username`, length must be less than or equal to `64`")  # noqa: E501

        self._username = username

    @property
    def password(self):
        """Gets the password of this RegistriesCredentials.  # noqa: E501

        (optional) Use this if your source requires requests to be authorized using basic username + password authentication. Requests will include an `Authorization: Basic {encoded username + password}` header.   # noqa: E501

        :return: The password of this RegistriesCredentials.  # noqa: E501
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, password):
        """Sets the password of this RegistriesCredentials.

        (optional) Use this if your source requires requests to be authorized using basic username + password authentication. Requests will include an `Authorization: Basic {encoded username + password}` header.   # noqa: E501

        :param password: The password of this RegistriesCredentials.  # noqa: E501
        :type: str
        """
        if password is not None and len(password) > 4096:
            raise ValueError("Invalid value for `password`, length must be less than or equal to `4096`")  # noqa: E501

        self._password = password

    @property
    def aws(self):
        """Gets the aws of this RegistriesCredentials.  # noqa: E501


        :return: The aws of this RegistriesCredentials.  # noqa: E501
        :rtype: ScansSourceCredentialsAws
        """
        return self._aws

    @aws.setter
    def aws(self, aws):
        """Sets the aws of this RegistriesCredentials.


        :param aws: The aws of this RegistriesCredentials.  # noqa: E501
        :type: ScansSourceCredentialsAws
        """

        self._aws = aws

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
        if not isinstance(other, RegistriesCredentials):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
