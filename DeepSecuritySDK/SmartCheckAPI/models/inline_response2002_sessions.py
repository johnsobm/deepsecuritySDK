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

from SmartCheckAPI.models.inline_response2001_users import InlineResponse2001Users  # noqa: F401,E501


class InlineResponse2002Sessions(object):
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
        'href': 'str',
        'user': 'InlineResponse2001Users',
        'token': 'str',
        'created': 'str',
        'updated': 'str',
        'expires': 'str'
    }

    attribute_map = {
        'id': 'id',
        'href': 'href',
        'user': 'user',
        'token': 'token',
        'created': 'created',
        'updated': 'updated',
        'expires': 'expires'
    }

    def __init__(self, id=None, href=None, user=None, token=None, created=None, updated=None, expires=None):  # noqa: E501
        """InlineResponse2002Sessions - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._href = None
        self._user = None
        self._token = None
        self._created = None
        self._updated = None
        self._expires = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if href is not None:
            self.href = href
        if user is not None:
            self.user = user
        if token is not None:
            self.token = token
        if created is not None:
            self.created = created
        if updated is not None:
            self.updated = updated
        if expires is not None:
            self.expires = expires

    @property
    def id(self):
        """Gets the id of this InlineResponse2002Sessions.  # noqa: E501

        The session's unique system identifier.   # noqa: E501

        :return: The id of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this InlineResponse2002Sessions.

        The session's unique system identifier.   # noqa: E501

        :param id: The id of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def href(self):
        """Gets the href of this InlineResponse2002Sessions.  # noqa: E501

        The URL at which the session can be found.   # noqa: E501

        :return: The href of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._href

    @href.setter
    def href(self, href):
        """Sets the href of this InlineResponse2002Sessions.

        The URL at which the session can be found.   # noqa: E501

        :param href: The href of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._href = href

    @property
    def user(self):
        """Gets the user of this InlineResponse2002Sessions.  # noqa: E501


        :return: The user of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: InlineResponse2001Users
        """
        return self._user

    @user.setter
    def user(self, user):
        """Sets the user of this InlineResponse2002Sessions.


        :param user: The user of this InlineResponse2002Sessions.  # noqa: E501
        :type: InlineResponse2001Users
        """

        self._user = user

    @property
    def token(self):
        """Gets the token of this InlineResponse2002Sessions.  # noqa: E501

        The session token. Use the session token the `Authorization` header of subsequent requests: ```Authorization: Bearer SAMPLEeyJhbGciOiJSUz...```   # noqa: E501

        :return: The token of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._token

    @token.setter
    def token(self, token):
        """Sets the token of this InlineResponse2002Sessions.

        The session token. Use the session token the `Authorization` header of subsequent requests: ```Authorization: Bearer SAMPLEeyJhbGciOiJSUz...```   # noqa: E501

        :param token: The token of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._token = token

    @property
    def created(self):
        """Gets the created of this InlineResponse2002Sessions.  # noqa: E501

        The time that the session was created.   # noqa: E501

        :return: The created of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this InlineResponse2002Sessions.

        The time that the session was created.   # noqa: E501

        :param created: The created of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._created = created

    @property
    def updated(self):
        """Gets the updated of this InlineResponse2002Sessions.  # noqa: E501

        The time that the session was last modified.   # noqa: E501

        :return: The updated of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this InlineResponse2002Sessions.

        The time that the session was last modified.   # noqa: E501

        :param updated: The updated of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._updated = updated

    @property
    def expires(self):
        """Gets the expires of this InlineResponse2002Sessions.  # noqa: E501

        The time that the session will expire.   # noqa: E501

        :return: The expires of this InlineResponse2002Sessions.  # noqa: E501
        :rtype: str
        """
        return self._expires

    @expires.setter
    def expires(self, expires):
        """Sets the expires of this InlineResponse2002Sessions.

        The time that the session will expire.   # noqa: E501

        :param expires: The expires of this InlineResponse2002Sessions.  # noqa: E501
        :type: str
        """

        self._expires = expires

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
        if not isinstance(other, InlineResponse2002Sessions):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
