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


class LicenseRights(object):
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
        'can_change_license': 'bool',
        'can_view_license': 'bool'
    }

    attribute_map = {
        'can_change_license': 'canChangeLicense',
        'can_view_license': 'canViewLicense'
    }

    def __init__(self, can_change_license=None, can_view_license=None):  # noqa: E501
        """LicenseRights - a model defined in Swagger"""  # noqa: E501

        self._can_change_license = None
        self._can_view_license = None
        self.discriminator = None

        if can_change_license is not None:
            self.can_change_license = can_change_license
        if can_view_license is not None:
            self.can_view_license = can_view_license

    @property
    def can_change_license(self):
        """Gets the can_change_license of this LicenseRights.  # noqa: E501

        Right to change license.  # noqa: E501

        :return: The can_change_license of this LicenseRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_change_license

    @can_change_license.setter
    def can_change_license(self, can_change_license):
        """Sets the can_change_license of this LicenseRights.

        Right to change license.  # noqa: E501

        :param can_change_license: The can_change_license of this LicenseRights.  # noqa: E501
        :type: bool
        """

        self._can_change_license = can_change_license

    @property
    def can_view_license(self):
        """Gets the can_view_license of this LicenseRights.  # noqa: E501

        Right to view license.  # noqa: E501

        :return: The can_view_license of this LicenseRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_license

    @can_view_license.setter
    def can_view_license(self, can_view_license):
        """Sets the can_view_license of this LicenseRights.

        Right to view license.  # noqa: E501

        :param can_view_license: The can_view_license of this LicenseRights.  # noqa: E501
        :type: bool
        """

        self._can_view_license = can_view_license

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
        if issubclass(LicenseRights, dict):
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
        if not isinstance(other, LicenseRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

