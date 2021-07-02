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


class IntrusionPreventionAssignments(object):
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
        'assigned_rule_ids': 'list[int]',
        'assigned_application_type_ids': 'list[int]',
        'recommendation_scan_status': 'str',
        'last_recommendation_scan_date': 'int',
        'recommended_to_assign_rule_ids': 'list[int]',
        'recommended_to_unassign_rule_ids': 'list[int]'
    }

    attribute_map = {
        'assigned_rule_ids': 'assignedRuleIDs',
        'assigned_application_type_ids': 'assignedApplicationTypeIDs',
        'recommendation_scan_status': 'recommendationScanStatus',
        'last_recommendation_scan_date': 'lastRecommendationScanDate',
        'recommended_to_assign_rule_ids': 'recommendedToAssignRuleIDs',
        'recommended_to_unassign_rule_ids': 'recommendedToUnassignRuleIDs'
    }

    def __init__(self, assigned_rule_ids=None, assigned_application_type_ids=None, recommendation_scan_status=None, last_recommendation_scan_date=None, recommended_to_assign_rule_ids=None, recommended_to_unassign_rule_ids=None):  # noqa: E501
        """IntrusionPreventionAssignments - a model defined in Swagger"""  # noqa: E501

        self._assigned_rule_ids = None
        self._assigned_application_type_ids = None
        self._recommendation_scan_status = None
        self._last_recommendation_scan_date = None
        self._recommended_to_assign_rule_ids = None
        self._recommended_to_unassign_rule_ids = None
        self.discriminator = None

        if assigned_rule_ids is not None:
            self.assigned_rule_ids = assigned_rule_ids
        if assigned_application_type_ids is not None:
            self.assigned_application_type_ids = assigned_application_type_ids
        if recommendation_scan_status is not None:
            self.recommendation_scan_status = recommendation_scan_status
        if last_recommendation_scan_date is not None:
            self.last_recommendation_scan_date = last_recommendation_scan_date
        if recommended_to_assign_rule_ids is not None:
            self.recommended_to_assign_rule_ids = recommended_to_assign_rule_ids
        if recommended_to_unassign_rule_ids is not None:
            self.recommended_to_unassign_rule_ids = recommended_to_unassign_rule_ids

    @property
    def assigned_rule_ids(self):
        """Gets the assigned_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501

        IDs of the intrusion prevention rules currently assigned.  # noqa: E501

        :return: The assigned_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._assigned_rule_ids

    @assigned_rule_ids.setter
    def assigned_rule_ids(self, assigned_rule_ids):
        """Sets the assigned_rule_ids of this IntrusionPreventionAssignments.

        IDs of the intrusion prevention rules currently assigned.  # noqa: E501

        :param assigned_rule_ids: The assigned_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :type: list[int]
        """

        self._assigned_rule_ids = assigned_rule_ids

    @property
    def assigned_application_type_ids(self):
        """Gets the assigned_application_type_ids of this IntrusionPreventionAssignments.  # noqa: E501

        IDs of the application types currently assigned.  # noqa: E501

        :return: The assigned_application_type_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._assigned_application_type_ids

    @assigned_application_type_ids.setter
    def assigned_application_type_ids(self, assigned_application_type_ids):
        """Sets the assigned_application_type_ids of this IntrusionPreventionAssignments.

        IDs of the application types currently assigned.  # noqa: E501

        :param assigned_application_type_ids: The assigned_application_type_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :type: list[int]
        """

        self._assigned_application_type_ids = assigned_application_type_ids

    @property
    def recommendation_scan_status(self):
        """Gets the recommendation_scan_status of this IntrusionPreventionAssignments.  # noqa: E501

        Status of the last recommendation scan.  # noqa: E501

        :return: The recommendation_scan_status of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: str
        """
        return self._recommendation_scan_status

    @recommendation_scan_status.setter
    def recommendation_scan_status(self, recommendation_scan_status):
        """Sets the recommendation_scan_status of this IntrusionPreventionAssignments.

        Status of the last recommendation scan.  # noqa: E501

        :param recommendation_scan_status: The recommendation_scan_status of this IntrusionPreventionAssignments.  # noqa: E501
        :type: str
        """
        allowed_values = ["none", "valid", "out-of-date", "unknown"]  # noqa: E501
        if recommendation_scan_status not in allowed_values:
            raise ValueError(
                "Invalid value for `recommendation_scan_status` ({0}), must be one of {1}"  # noqa: E501
                .format(recommendation_scan_status, allowed_values)
            )

        self._recommendation_scan_status = recommendation_scan_status

    @property
    def last_recommendation_scan_date(self):
        """Gets the last_recommendation_scan_date of this IntrusionPreventionAssignments.  # noqa: E501

        Timestamp of the last recommendation scan, in milliseconds since epoch.  # noqa: E501

        :return: The last_recommendation_scan_date of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: int
        """
        return self._last_recommendation_scan_date

    @last_recommendation_scan_date.setter
    def last_recommendation_scan_date(self, last_recommendation_scan_date):
        """Sets the last_recommendation_scan_date of this IntrusionPreventionAssignments.

        Timestamp of the last recommendation scan, in milliseconds since epoch.  # noqa: E501

        :param last_recommendation_scan_date: The last_recommendation_scan_date of this IntrusionPreventionAssignments.  # noqa: E501
        :type: int
        """

        self._last_recommendation_scan_date = last_recommendation_scan_date

    @property
    def recommended_to_assign_rule_ids(self):
        """Gets the recommended_to_assign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501

        IDs of the intrusion prevention rules recommended for assignment.  # noqa: E501

        :return: The recommended_to_assign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._recommended_to_assign_rule_ids

    @recommended_to_assign_rule_ids.setter
    def recommended_to_assign_rule_ids(self, recommended_to_assign_rule_ids):
        """Sets the recommended_to_assign_rule_ids of this IntrusionPreventionAssignments.

        IDs of the intrusion prevention rules recommended for assignment.  # noqa: E501

        :param recommended_to_assign_rule_ids: The recommended_to_assign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :type: list[int]
        """

        self._recommended_to_assign_rule_ids = recommended_to_assign_rule_ids

    @property
    def recommended_to_unassign_rule_ids(self):
        """Gets the recommended_to_unassign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501

        IDs of the intrusion prevention rules recommended for unassignment.  # noqa: E501

        :return: The recommended_to_unassign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :rtype: list[int]
        """
        return self._recommended_to_unassign_rule_ids

    @recommended_to_unassign_rule_ids.setter
    def recommended_to_unassign_rule_ids(self, recommended_to_unassign_rule_ids):
        """Sets the recommended_to_unassign_rule_ids of this IntrusionPreventionAssignments.

        IDs of the intrusion prevention rules recommended for unassignment.  # noqa: E501

        :param recommended_to_unassign_rule_ids: The recommended_to_unassign_rule_ids of this IntrusionPreventionAssignments.  # noqa: E501
        :type: list[int]
        """

        self._recommended_to_unassign_rule_ids = recommended_to_unassign_rule_ids

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
        if issubclass(IntrusionPreventionAssignments, dict):
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
        if not isinstance(other, IntrusionPreventionAssignments):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

