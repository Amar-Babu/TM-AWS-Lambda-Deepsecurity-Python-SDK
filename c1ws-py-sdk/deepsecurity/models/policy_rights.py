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


class PolicyRights(object):
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
        'can_create_new_policies': 'bool',
        'can_delete_policies': 'bool',
        'can_edit_policy_properties': 'bool',
        'can_import_policies': 'bool',
        'can_view_other_policies': 'bool'
    }

    attribute_map = {
        'can_create_new_policies': 'canCreateNewPolicies',
        'can_delete_policies': 'canDeletePolicies',
        'can_edit_policy_properties': 'canEditPolicyProperties',
        'can_import_policies': 'canImportPolicies',
        'can_view_other_policies': 'canViewOtherPolicies'
    }

    def __init__(self, can_create_new_policies=None, can_delete_policies=None, can_edit_policy_properties=None, can_import_policies=None, can_view_other_policies=None):  # noqa: E501
        """PolicyRights - a model defined in Swagger"""  # noqa: E501

        self._can_create_new_policies = None
        self._can_delete_policies = None
        self._can_edit_policy_properties = None
        self._can_import_policies = None
        self._can_view_other_policies = None
        self.discriminator = None

        if can_create_new_policies is not None:
            self.can_create_new_policies = can_create_new_policies
        if can_delete_policies is not None:
            self.can_delete_policies = can_delete_policies
        if can_edit_policy_properties is not None:
            self.can_edit_policy_properties = can_edit_policy_properties
        if can_import_policies is not None:
            self.can_import_policies = can_import_policies
        if can_view_other_policies is not None:
            self.can_view_other_policies = can_view_other_policies

    @property
    def can_create_new_policies(self):
        """Gets the can_create_new_policies of this PolicyRights.  # noqa: E501

        Right to create new policies.  # noqa: E501

        :return: The can_create_new_policies of this PolicyRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_create_new_policies

    @can_create_new_policies.setter
    def can_create_new_policies(self, can_create_new_policies):
        """Sets the can_create_new_policies of this PolicyRights.

        Right to create new policies.  # noqa: E501

        :param can_create_new_policies: The can_create_new_policies of this PolicyRights.  # noqa: E501
        :type: bool
        """

        self._can_create_new_policies = can_create_new_policies

    @property
    def can_delete_policies(self):
        """Gets the can_delete_policies of this PolicyRights.  # noqa: E501

        Right to delete policies.  # noqa: E501

        :return: The can_delete_policies of this PolicyRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete_policies

    @can_delete_policies.setter
    def can_delete_policies(self, can_delete_policies):
        """Sets the can_delete_policies of this PolicyRights.

        Right to delete policies.  # noqa: E501

        :param can_delete_policies: The can_delete_policies of this PolicyRights.  # noqa: E501
        :type: bool
        """

        self._can_delete_policies = can_delete_policies

    @property
    def can_edit_policy_properties(self):
        """Gets the can_edit_policy_properties of this PolicyRights.  # noqa: E501

        Right to edit policy properties.  # noqa: E501

        :return: The can_edit_policy_properties of this PolicyRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_edit_policy_properties

    @can_edit_policy_properties.setter
    def can_edit_policy_properties(self, can_edit_policy_properties):
        """Sets the can_edit_policy_properties of this PolicyRights.

        Right to edit policy properties.  # noqa: E501

        :param can_edit_policy_properties: The can_edit_policy_properties of this PolicyRights.  # noqa: E501
        :type: bool
        """

        self._can_edit_policy_properties = can_edit_policy_properties

    @property
    def can_import_policies(self):
        """Gets the can_import_policies of this PolicyRights.  # noqa: E501

        Right to import policies.  # noqa: E501

        :return: The can_import_policies of this PolicyRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_import_policies

    @can_import_policies.setter
    def can_import_policies(self, can_import_policies):
        """Sets the can_import_policies of this PolicyRights.

        Right to import policies.  # noqa: E501

        :param can_import_policies: The can_import_policies of this PolicyRights.  # noqa: E501
        :type: bool
        """

        self._can_import_policies = can_import_policies

    @property
    def can_view_other_policies(self):
        """Gets the can_view_other_policies of this PolicyRights.  # noqa: E501

        Right to view non-selected policies.  # noqa: E501

        :return: The can_view_other_policies of this PolicyRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_other_policies

    @can_view_other_policies.setter
    def can_view_other_policies(self, can_view_other_policies):
        """Sets the can_view_other_policies of this PolicyRights.

        Right to view non-selected policies.  # noqa: E501

        :param can_view_other_policies: The can_view_other_policies of this PolicyRights.  # noqa: E501
        :type: bool
        """

        self._can_view_other_policies = can_view_other_policies

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
        if issubclass(PolicyRights, dict):
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
        if not isinstance(other, PolicyRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

