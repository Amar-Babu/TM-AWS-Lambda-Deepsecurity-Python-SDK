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


class DriftRights(object):
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
        'can_allow_or_block_drift': 'bool',
        'can_view_drift': 'bool'
    }

    attribute_map = {
        'can_allow_or_block_drift': 'canAllowOrBlockDrift',
        'can_view_drift': 'canViewDrift'
    }

    def __init__(self, can_allow_or_block_drift=None, can_view_drift=None):  # noqa: E501
        """DriftRights - a model defined in Swagger"""  # noqa: E501

        self._can_allow_or_block_drift = None
        self._can_view_drift = None
        self.discriminator = None

        if can_allow_or_block_drift is not None:
            self.can_allow_or_block_drift = can_allow_or_block_drift
        if can_view_drift is not None:
            self.can_view_drift = can_view_drift

    @property
    def can_allow_or_block_drift(self):
        """Gets the can_allow_or_block_drift of this DriftRights.  # noqa: E501

        Right to allow or block unrecognized software.  # noqa: E501

        :return: The can_allow_or_block_drift of this DriftRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_allow_or_block_drift

    @can_allow_or_block_drift.setter
    def can_allow_or_block_drift(self, can_allow_or_block_drift):
        """Sets the can_allow_or_block_drift of this DriftRights.

        Right to allow or block unrecognized software.  # noqa: E501

        :param can_allow_or_block_drift: The can_allow_or_block_drift of this DriftRights.  # noqa: E501
        :type: bool
        """

        self._can_allow_or_block_drift = can_allow_or_block_drift

    @property
    def can_view_drift(self):
        """Gets the can_view_drift of this DriftRights.  # noqa: E501

        Right to view unrecognized software.  # noqa: E501

        :return: The can_view_drift of this DriftRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_drift

    @can_view_drift.setter
    def can_view_drift(self, can_view_drift):
        """Sets the can_view_drift of this DriftRights.

        Right to view unrecognized software.  # noqa: E501

        :param can_view_drift: The can_view_drift of this DriftRights.  # noqa: E501
        :type: bool
        """

        self._can_view_drift = can_view_drift

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
        if issubclass(DriftRights, dict):
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
        if not isinstance(other, DriftRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

