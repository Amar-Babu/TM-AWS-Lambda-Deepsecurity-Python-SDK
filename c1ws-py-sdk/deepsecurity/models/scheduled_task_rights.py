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


class ScheduledTaskRights(object):
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
        'can_create_new_scheduled_tasks': 'bool',
        'can_delete_scheduled_tasks': 'bool',
        'can_edit_scheduled_task_properties': 'bool',
        'can_execute_scheduled_tasks': 'bool',
        'can_view_scheduled_tasks': 'bool'
    }

    attribute_map = {
        'can_create_new_scheduled_tasks': 'canCreateNewScheduledTasks',
        'can_delete_scheduled_tasks': 'canDeleteScheduledTasks',
        'can_edit_scheduled_task_properties': 'canEditScheduledTaskProperties',
        'can_execute_scheduled_tasks': 'canExecuteScheduledTasks',
        'can_view_scheduled_tasks': 'canViewScheduledTasks'
    }

    def __init__(self, can_create_new_scheduled_tasks=None, can_delete_scheduled_tasks=None, can_edit_scheduled_task_properties=None, can_execute_scheduled_tasks=None, can_view_scheduled_tasks=None):  # noqa: E501
        """ScheduledTaskRights - a model defined in Swagger"""  # noqa: E501

        self._can_create_new_scheduled_tasks = None
        self._can_delete_scheduled_tasks = None
        self._can_edit_scheduled_task_properties = None
        self._can_execute_scheduled_tasks = None
        self._can_view_scheduled_tasks = None
        self.discriminator = None

        if can_create_new_scheduled_tasks is not None:
            self.can_create_new_scheduled_tasks = can_create_new_scheduled_tasks
        if can_delete_scheduled_tasks is not None:
            self.can_delete_scheduled_tasks = can_delete_scheduled_tasks
        if can_edit_scheduled_task_properties is not None:
            self.can_edit_scheduled_task_properties = can_edit_scheduled_task_properties
        if can_execute_scheduled_tasks is not None:
            self.can_execute_scheduled_tasks = can_execute_scheduled_tasks
        if can_view_scheduled_tasks is not None:
            self.can_view_scheduled_tasks = can_view_scheduled_tasks

    @property
    def can_create_new_scheduled_tasks(self):
        """Gets the can_create_new_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501

        Right to create new scheduled tasks.  # noqa: E501

        :return: The can_create_new_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_create_new_scheduled_tasks

    @can_create_new_scheduled_tasks.setter
    def can_create_new_scheduled_tasks(self, can_create_new_scheduled_tasks):
        """Sets the can_create_new_scheduled_tasks of this ScheduledTaskRights.

        Right to create new scheduled tasks.  # noqa: E501

        :param can_create_new_scheduled_tasks: The can_create_new_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :type: bool
        """

        self._can_create_new_scheduled_tasks = can_create_new_scheduled_tasks

    @property
    def can_delete_scheduled_tasks(self):
        """Gets the can_delete_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501

        Right to delete scheduled tasks.  # noqa: E501

        :return: The can_delete_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete_scheduled_tasks

    @can_delete_scheduled_tasks.setter
    def can_delete_scheduled_tasks(self, can_delete_scheduled_tasks):
        """Sets the can_delete_scheduled_tasks of this ScheduledTaskRights.

        Right to delete scheduled tasks.  # noqa: E501

        :param can_delete_scheduled_tasks: The can_delete_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :type: bool
        """

        self._can_delete_scheduled_tasks = can_delete_scheduled_tasks

    @property
    def can_edit_scheduled_task_properties(self):
        """Gets the can_edit_scheduled_task_properties of this ScheduledTaskRights.  # noqa: E501

        Right to edit scheduled task properties.  # noqa: E501

        :return: The can_edit_scheduled_task_properties of this ScheduledTaskRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_edit_scheduled_task_properties

    @can_edit_scheduled_task_properties.setter
    def can_edit_scheduled_task_properties(self, can_edit_scheduled_task_properties):
        """Sets the can_edit_scheduled_task_properties of this ScheduledTaskRights.

        Right to edit scheduled task properties.  # noqa: E501

        :param can_edit_scheduled_task_properties: The can_edit_scheduled_task_properties of this ScheduledTaskRights.  # noqa: E501
        :type: bool
        """

        self._can_edit_scheduled_task_properties = can_edit_scheduled_task_properties

    @property
    def can_execute_scheduled_tasks(self):
        """Gets the can_execute_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501

        Right to execute scheduled tasks.  # noqa: E501

        :return: The can_execute_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_execute_scheduled_tasks

    @can_execute_scheduled_tasks.setter
    def can_execute_scheduled_tasks(self, can_execute_scheduled_tasks):
        """Sets the can_execute_scheduled_tasks of this ScheduledTaskRights.

        Right to execute scheduled tasks.  # noqa: E501

        :param can_execute_scheduled_tasks: The can_execute_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :type: bool
        """

        self._can_execute_scheduled_tasks = can_execute_scheduled_tasks

    @property
    def can_view_scheduled_tasks(self):
        """Gets the can_view_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501

        Right to view scheduled tasks.  # noqa: E501

        :return: The can_view_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_scheduled_tasks

    @can_view_scheduled_tasks.setter
    def can_view_scheduled_tasks(self, can_view_scheduled_tasks):
        """Sets the can_view_scheduled_tasks of this ScheduledTaskRights.

        Right to view scheduled tasks.  # noqa: E501

        :param can_view_scheduled_tasks: The can_view_scheduled_tasks of this ScheduledTaskRights.  # noqa: E501
        :type: bool
        """

        self._can_view_scheduled_tasks = can_view_scheduled_tasks

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
        if issubclass(ScheduledTaskRights, dict):
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
        if not isinstance(other, ScheduledTaskRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

