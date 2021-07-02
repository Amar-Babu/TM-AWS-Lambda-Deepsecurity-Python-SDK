# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2020 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 20.0.242
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class VCenterInfo(object):
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
        'host': 'str',
        'port': 'int',
        'name': 'str',
        'description': 'str',
        'username': 'str',
        'password': 'str'
    }

    attribute_map = {
        'host': 'host',
        'port': 'port',
        'name': 'name',
        'description': 'description',
        'username': 'username',
        'password': 'password'
    }

    def __init__(self, host=None, port=None, name=None, description=None, username=None, password=None):  # noqa: E501
        """VCenterInfo - a model defined in Swagger"""  # noqa: E501

        self._host = None
        self._port = None
        self._name = None
        self._description = None
        self._username = None
        self._password = None
        self.discriminator = None

        if host is not None:
            self.host = host
        if port is not None:
            self.port = port
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password

    @property
    def host(self):
        """Gets the host of this VCenterInfo.  # noqa: E501

        vCenter server address.  # noqa: E501

        :return: The host of this VCenterInfo.  # noqa: E501
        :rtype: str
        """
        return self._host

    @host.setter
    def host(self, host):
        """Sets the host of this VCenterInfo.

        vCenter server address.  # noqa: E501

        :param host: The host of this VCenterInfo.  # noqa: E501
        :type: str
        """

        self._host = host

    @property
    def port(self):
        """Gets the port of this VCenterInfo.  # noqa: E501

        vCenter server port.  # noqa: E501

        :return: The port of this VCenterInfo.  # noqa: E501
        :rtype: int
        """
        return self._port

    @port.setter
    def port(self, port):
        """Sets the port of this VCenterInfo.

        vCenter server port.  # noqa: E501

        :param port: The port of this VCenterInfo.  # noqa: E501
        :type: int
        """

        self._port = port

    @property
    def name(self):
        """Gets the name of this VCenterInfo.  # noqa: E501

        Display name of the connector.  # noqa: E501

        :return: The name of this VCenterInfo.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this VCenterInfo.

        Display name of the connector.  # noqa: E501

        :param name: The name of this VCenterInfo.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this VCenterInfo.  # noqa: E501

        Description of the connector.  # noqa: E501

        :return: The description of this VCenterInfo.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this VCenterInfo.

        Description of the connector.  # noqa: E501

        :param description: The description of this VCenterInfo.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def username(self):
        """Gets the username of this VCenterInfo.  # noqa: E501

        Username that the connector will use to authenticate to vCenter.  # noqa: E501

        :return: The username of this VCenterInfo.  # noqa: E501
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """Sets the username of this VCenterInfo.

        Username that the connector will use to authenticate to vCenter.  # noqa: E501

        :param username: The username of this VCenterInfo.  # noqa: E501
        :type: str
        """

        self._username = username

    @property
    def password(self):
        """Gets the password of this VCenterInfo.  # noqa: E501

        Password of the vCenter user. Must be base64-encoded.  # noqa: E501

        :return: The password of this VCenterInfo.  # noqa: E501
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, password):
        """Sets the password of this VCenterInfo.

        Password of the vCenter user. Must be base64-encoded.  # noqa: E501

        :param password: The password of this VCenterInfo.  # noqa: E501
        :type: str
        """

        self._password = password

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
        if issubclass(VCenterInfo, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, VCenterInfo):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
