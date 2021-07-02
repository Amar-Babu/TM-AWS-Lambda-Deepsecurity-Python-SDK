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


class SynchronizeCloudAccountTaskParameters(object):
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
        'computer_group_id': 'int'
    }

    attribute_map = {
        'computer_group_id': 'computerGroupID'
    }

    def __init__(self, computer_group_id=None):  # noqa: E501
        """SynchronizeCloudAccountTaskParameters - a model defined in Swagger"""  # noqa: E501

        self._computer_group_id = None
        self.discriminator = None

        if computer_group_id is not None:
            self.computer_group_id = computer_group_id

    @property
    def computer_group_id(self):
        """Gets the computer_group_id of this SynchronizeCloudAccountTaskParameters.  # noqa: E501

        Identifies the top-level computer group for the cloud.  # noqa: E501

        :return: The computer_group_id of this SynchronizeCloudAccountTaskParameters.  # noqa: E501
        :rtype: int
        """
        return self._computer_group_id

    @computer_group_id.setter
    def computer_group_id(self, computer_group_id):
        """Sets the computer_group_id of this SynchronizeCloudAccountTaskParameters.

        Identifies the top-level computer group for the cloud.  # noqa: E501

        :param computer_group_id: The computer_group_id of this SynchronizeCloudAccountTaskParameters.  # noqa: E501
        :type: int
        """

        self._computer_group_id = computer_group_id

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
        if issubclass(SynchronizeCloudAccountTaskParameters, dict):
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
        if not isinstance(other, SynchronizeCloudAccountTaskParameters):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

