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


class ComputerRights(object):
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
        'can_add_and_remove_computer_groups': 'bool',
        'can_create_new_computers': 'bool',
        'can_delete_computers': 'bool',
        'can_dismiss_alerts': 'bool',
        'can_edit_computer_properties': 'bool',
        'can_import_computers': 'bool',
        'can_manage_cloud_accounts': 'bool',
        'can_manage_directories': 'bool',
        'can_manage_v_centers': 'bool',
        'can_tag_computers': 'bool',
        'can_view_not_related_to_computers': 'bool',
        'can_view_other_computers': 'bool'
    }

    attribute_map = {
        'can_add_and_remove_computer_groups': 'canAddAndRemoveComputerGroups',
        'can_create_new_computers': 'canCreateNewComputers',
        'can_delete_computers': 'canDeleteComputers',
        'can_dismiss_alerts': 'canDismissAlerts',
        'can_edit_computer_properties': 'canEditComputerProperties',
        'can_import_computers': 'canImportComputers',
        'can_manage_cloud_accounts': 'canManageCloudAccounts',
        'can_manage_directories': 'canManageDirectories',
        'can_manage_v_centers': 'canManageVCenters',
        'can_tag_computers': 'canTagComputers',
        'can_view_not_related_to_computers': 'canViewNotRelatedToComputers',
        'can_view_other_computers': 'canViewOtherComputers'
    }

    def __init__(self, can_add_and_remove_computer_groups=None, can_create_new_computers=None, can_delete_computers=None, can_dismiss_alerts=None, can_edit_computer_properties=None, can_import_computers=None, can_manage_cloud_accounts=None, can_manage_directories=None, can_manage_v_centers=None, can_tag_computers=None, can_view_not_related_to_computers=None, can_view_other_computers=None):  # noqa: E501
        """ComputerRights - a model defined in Swagger"""  # noqa: E501

        self._can_add_and_remove_computer_groups = None
        self._can_create_new_computers = None
        self._can_delete_computers = None
        self._can_dismiss_alerts = None
        self._can_edit_computer_properties = None
        self._can_import_computers = None
        self._can_manage_cloud_accounts = None
        self._can_manage_directories = None
        self._can_manage_v_centers = None
        self._can_tag_computers = None
        self._can_view_not_related_to_computers = None
        self._can_view_other_computers = None
        self.discriminator = None

        if can_add_and_remove_computer_groups is not None:
            self.can_add_and_remove_computer_groups = can_add_and_remove_computer_groups
        if can_create_new_computers is not None:
            self.can_create_new_computers = can_create_new_computers
        if can_delete_computers is not None:
            self.can_delete_computers = can_delete_computers
        if can_dismiss_alerts is not None:
            self.can_dismiss_alerts = can_dismiss_alerts
        if can_edit_computer_properties is not None:
            self.can_edit_computer_properties = can_edit_computer_properties
        if can_import_computers is not None:
            self.can_import_computers = can_import_computers
        if can_manage_cloud_accounts is not None:
            self.can_manage_cloud_accounts = can_manage_cloud_accounts
        if can_manage_directories is not None:
            self.can_manage_directories = can_manage_directories
        if can_manage_v_centers is not None:
            self.can_manage_v_centers = can_manage_v_centers
        if can_tag_computers is not None:
            self.can_tag_computers = can_tag_computers
        if can_view_not_related_to_computers is not None:
            self.can_view_not_related_to_computers = can_view_not_related_to_computers
        if can_view_other_computers is not None:
            self.can_view_other_computers = can_view_other_computers

    @property
    def can_add_and_remove_computer_groups(self):
        """Gets the can_add_and_remove_computer_groups of this ComputerRights.  # noqa: E501

        Right to add and remove computer groups.  # noqa: E501

        :return: The can_add_and_remove_computer_groups of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_add_and_remove_computer_groups

    @can_add_and_remove_computer_groups.setter
    def can_add_and_remove_computer_groups(self, can_add_and_remove_computer_groups):
        """Sets the can_add_and_remove_computer_groups of this ComputerRights.

        Right to add and remove computer groups.  # noqa: E501

        :param can_add_and_remove_computer_groups: The can_add_and_remove_computer_groups of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_add_and_remove_computer_groups = can_add_and_remove_computer_groups

    @property
    def can_create_new_computers(self):
        """Gets the can_create_new_computers of this ComputerRights.  # noqa: E501

        Right to create new computers.  # noqa: E501

        :return: The can_create_new_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_create_new_computers

    @can_create_new_computers.setter
    def can_create_new_computers(self, can_create_new_computers):
        """Sets the can_create_new_computers of this ComputerRights.

        Right to create new computers.  # noqa: E501

        :param can_create_new_computers: The can_create_new_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_create_new_computers = can_create_new_computers

    @property
    def can_delete_computers(self):
        """Gets the can_delete_computers of this ComputerRights.  # noqa: E501

        Right to delete computers.  # noqa: E501

        :return: The can_delete_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete_computers

    @can_delete_computers.setter
    def can_delete_computers(self, can_delete_computers):
        """Sets the can_delete_computers of this ComputerRights.

        Right to delete computers.  # noqa: E501

        :param can_delete_computers: The can_delete_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_delete_computers = can_delete_computers

    @property
    def can_dismiss_alerts(self):
        """Gets the can_dismiss_alerts of this ComputerRights.  # noqa: E501

        Right to dismiss computer alerts.  # noqa: E501

        :return: The can_dismiss_alerts of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_dismiss_alerts

    @can_dismiss_alerts.setter
    def can_dismiss_alerts(self, can_dismiss_alerts):
        """Sets the can_dismiss_alerts of this ComputerRights.

        Right to dismiss computer alerts.  # noqa: E501

        :param can_dismiss_alerts: The can_dismiss_alerts of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_dismiss_alerts = can_dismiss_alerts

    @property
    def can_edit_computer_properties(self):
        """Gets the can_edit_computer_properties of this ComputerRights.  # noqa: E501

        Right to edit computer properties.  # noqa: E501

        :return: The can_edit_computer_properties of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_edit_computer_properties

    @can_edit_computer_properties.setter
    def can_edit_computer_properties(self, can_edit_computer_properties):
        """Sets the can_edit_computer_properties of this ComputerRights.

        Right to edit computer properties.  # noqa: E501

        :param can_edit_computer_properties: The can_edit_computer_properties of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_edit_computer_properties = can_edit_computer_properties

    @property
    def can_import_computers(self):
        """Gets the can_import_computers of this ComputerRights.  # noqa: E501

        Right to import computers.  # noqa: E501

        :return: The can_import_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_import_computers

    @can_import_computers.setter
    def can_import_computers(self, can_import_computers):
        """Sets the can_import_computers of this ComputerRights.

        Right to import computers.  # noqa: E501

        :param can_import_computers: The can_import_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_import_computers = can_import_computers

    @property
    def can_manage_cloud_accounts(self):
        """Gets the can_manage_cloud_accounts of this ComputerRights.  # noqa: E501

        Right to manage cloud accounts.  # noqa: E501

        :return: The can_manage_cloud_accounts of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_manage_cloud_accounts

    @can_manage_cloud_accounts.setter
    def can_manage_cloud_accounts(self, can_manage_cloud_accounts):
        """Sets the can_manage_cloud_accounts of this ComputerRights.

        Right to manage cloud accounts.  # noqa: E501

        :param can_manage_cloud_accounts: The can_manage_cloud_accounts of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_manage_cloud_accounts = can_manage_cloud_accounts

    @property
    def can_manage_directories(self):
        """Gets the can_manage_directories of this ComputerRights.  # noqa: E501

        Right to manage directories.  # noqa: E501

        :return: The can_manage_directories of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_manage_directories

    @can_manage_directories.setter
    def can_manage_directories(self, can_manage_directories):
        """Sets the can_manage_directories of this ComputerRights.

        Right to manage directories.  # noqa: E501

        :param can_manage_directories: The can_manage_directories of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_manage_directories = can_manage_directories

    @property
    def can_manage_v_centers(self):
        """Gets the can_manage_v_centers of this ComputerRights.  # noqa: E501

        Right to manage VMware vCenters.  # noqa: E501

        :return: The can_manage_v_centers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_manage_v_centers

    @can_manage_v_centers.setter
    def can_manage_v_centers(self, can_manage_v_centers):
        """Sets the can_manage_v_centers of this ComputerRights.

        Right to manage VMware vCenters.  # noqa: E501

        :param can_manage_v_centers: The can_manage_v_centers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_manage_v_centers = can_manage_v_centers

    @property
    def can_tag_computers(self):
        """Gets the can_tag_computers of this ComputerRights.  # noqa: E501

        Right to tag computers.  # noqa: E501

        :return: The can_tag_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_tag_computers

    @can_tag_computers.setter
    def can_tag_computers(self, can_tag_computers):
        """Sets the can_tag_computers of this ComputerRights.

        Right to tag computers.  # noqa: E501

        :param can_tag_computers: The can_tag_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_tag_computers = can_tag_computers

    @property
    def can_view_not_related_to_computers(self):
        """Gets the can_view_not_related_to_computers of this ComputerRights.  # noqa: E501

        Right to view events and alerts not related to computers.  # noqa: E501

        :return: The can_view_not_related_to_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_not_related_to_computers

    @can_view_not_related_to_computers.setter
    def can_view_not_related_to_computers(self, can_view_not_related_to_computers):
        """Sets the can_view_not_related_to_computers of this ComputerRights.

        Right to view events and alerts not related to computers.  # noqa: E501

        :param can_view_not_related_to_computers: The can_view_not_related_to_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_view_not_related_to_computers = can_view_not_related_to_computers

    @property
    def can_view_other_computers(self):
        """Gets the can_view_other_computers of this ComputerRights.  # noqa: E501

        Right to view non-selected computers.  # noqa: E501

        :return: The can_view_other_computers of this ComputerRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_other_computers

    @can_view_other_computers.setter
    def can_view_other_computers(self, can_view_other_computers):
        """Sets the can_view_other_computers of this ComputerRights.

        Right to view non-selected computers.  # noqa: E501

        :param can_view_other_computers: The can_view_other_computers of this ComputerRights.  # noqa: E501
        :type: bool
        """

        self._can_view_other_computers = can_view_other_computers

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
        if issubclass(ComputerRights, dict):
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
        if not isinstance(other, ComputerRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

