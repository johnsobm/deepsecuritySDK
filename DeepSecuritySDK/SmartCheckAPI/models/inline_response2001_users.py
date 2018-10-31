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


class InlineResponse2001Users(object):
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
        'user_id': 'str',
        'name': 'str',
        'description': 'str',
        'role': 'str',
        'password_change_required': 'bool',
        'created': 'str',
        'updated': 'str'
    }

    attribute_map = {
        'id': 'id',
        'href': 'href',
        'user_id': 'userID',
        'name': 'name',
        'description': 'description',
        'role': 'role',
        'password_change_required': 'passwordChangeRequired',
        'created': 'created',
        'updated': 'updated'
    }

    def __init__(self, id=None, href=None, user_id=None, name=None, description=None, role=None, password_change_required=None, created=None, updated=None):  # noqa: E501
        """InlineResponse2001Users - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._href = None
        self._user_id = None
        self._name = None
        self._description = None
        self._role = None
        self._password_change_required = None
        self._created = None
        self._updated = None
        self.discriminator = None

        self.id = id
        self.href = href
        self.user_id = user_id
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        self.role = role
        if password_change_required is not None:
            self.password_change_required = password_change_required
        self.created = created
        self.updated = updated

    @property
    def id(self):
        """Gets the id of this InlineResponse2001Users.  # noqa: E501

        The user's unique system identifier.   # noqa: E501

        :return: The id of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this InlineResponse2001Users.

        The user's unique system identifier.   # noqa: E501

        :param id: The id of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if id is None:
            raise ValueError("Invalid value for `id`, must not be `None`")  # noqa: E501

        self._id = id

    @property
    def href(self):
        """Gets the href of this InlineResponse2001Users.  # noqa: E501

        The URL at which the user can be found.   # noqa: E501

        :return: The href of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._href

    @href.setter
    def href(self, href):
        """Sets the href of this InlineResponse2001Users.

        The URL at which the user can be found.   # noqa: E501

        :param href: The href of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if href is None:
            raise ValueError("Invalid value for `href`, must not be `None`")  # noqa: E501

        self._href = href

    @property
    def user_id(self):
        """Gets the user_id of this InlineResponse2001Users.  # noqa: E501

        A unique name for the user.   # noqa: E501

        :return: The user_id of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """Sets the user_id of this InlineResponse2001Users.

        A unique name for the user.   # noqa: E501

        :param user_id: The user_id of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if user_id is None:
            raise ValueError("Invalid value for `user_id`, must not be `None`")  # noqa: E501
        if user_id is not None and len(user_id) > 64:
            raise ValueError("Invalid value for `user_id`, length must be less than or equal to `64`")  # noqa: E501

        self._user_id = user_id

    @property
    def name(self):
        """Gets the name of this InlineResponse2001Users.  # noqa: E501

        A display name for the user.   # noqa: E501

        :return: The name of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this InlineResponse2001Users.

        A display name for the user.   # noqa: E501

        :param name: The name of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if name is not None and len(name) > 128:
            raise ValueError("Invalid value for `name`, length must be less than or equal to `128`")  # noqa: E501

        self._name = name

    @property
    def description(self):
        """Gets the description of this InlineResponse2001Users.  # noqa: E501

        A description for the user.   # noqa: E501

        :return: The description of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this InlineResponse2001Users.

        A description for the user.   # noqa: E501

        :param description: The description of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if description is not None and len(description) > 2048:
            raise ValueError("Invalid value for `description`, length must be less than or equal to `2048`")  # noqa: E501

        self._description = description

    @property
    def role(self):
        """Gets the role of this InlineResponse2001Users.  # noqa: E501

        The user's role identifier.   # noqa: E501

        :return: The role of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._role

    @role.setter
    def role(self, role):
        """Sets the role of this InlineResponse2001Users.

        The user's role identifier.   # noqa: E501

        :param role: The role of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if role is None:
            raise ValueError("Invalid value for `role`, must not be `None`")  # noqa: E501

        self._role = role

    @property
    def password_change_required(self):
        """Gets the password_change_required of this InlineResponse2001Users.  # noqa: E501

        If `true`, the user will not be able to perform any actions until they change their password.   # noqa: E501

        :return: The password_change_required of this InlineResponse2001Users.  # noqa: E501
        :rtype: bool
        """
        return self._password_change_required

    @password_change_required.setter
    def password_change_required(self, password_change_required):
        """Sets the password_change_required of this InlineResponse2001Users.

        If `true`, the user will not be able to perform any actions until they change their password.   # noqa: E501

        :param password_change_required: The password_change_required of this InlineResponse2001Users.  # noqa: E501
        :type: bool
        """

        self._password_change_required = password_change_required

    @property
    def created(self):
        """Gets the created of this InlineResponse2001Users.  # noqa: E501

        The time that the user was created.   # noqa: E501

        :return: The created of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this InlineResponse2001Users.

        The time that the user was created.   # noqa: E501

        :param created: The created of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if created is None:
            raise ValueError("Invalid value for `created`, must not be `None`")  # noqa: E501

        self._created = created

    @property
    def updated(self):
        """Gets the updated of this InlineResponse2001Users.  # noqa: E501

        The time that the user was last modified.   # noqa: E501

        :return: The updated of this InlineResponse2001Users.  # noqa: E501
        :rtype: str
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this InlineResponse2001Users.

        The time that the user was last modified.   # noqa: E501

        :param updated: The updated of this InlineResponse2001Users.  # noqa: E501
        :type: str
        """
        if updated is None:
            raise ValueError("Invalid value for `updated`, must not be `None`")  # noqa: E501

        self._updated = updated

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
        if not isinstance(other, InlineResponse2001Users):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
