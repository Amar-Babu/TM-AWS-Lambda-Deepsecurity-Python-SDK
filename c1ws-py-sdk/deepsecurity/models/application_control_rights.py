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

from deepsecurity.models.drift_rights import DriftRights  # noqa: F401,E501
from deepsecurity.models.rule_rights import RuleRights  # noqa: F401,E501
from deepsecurity.models.ruleset_rights import RulesetRights  # noqa: F401,E501
from deepsecurity.models.software_inventory_rights import SoftwareInventoryRights  # noqa: F401,E501


class ApplicationControlRights(object):
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
        'drift_rights': 'DriftRights',
        'ruleset_rights': 'RulesetRights',
        'rule_rights': 'RuleRights',
        'software_inventory_rights': 'SoftwareInventoryRights'
    }

    attribute_map = {
        'drift_rights': 'driftRights',
        'ruleset_rights': 'rulesetRights',
        'rule_rights': 'ruleRights',
        'software_inventory_rights': 'softwareInventoryRights'
    }

    def __init__(self, drift_rights=None, ruleset_rights=None, rule_rights=None, software_inventory_rights=None):  # noqa: E501
        """ApplicationControlRights - a model defined in Swagger"""  # noqa: E501

        self._drift_rights = None
        self._ruleset_rights = None
        self._rule_rights = None
        self._software_inventory_rights = None
        self.discriminator = None

        if drift_rights is not None:
            self.drift_rights = drift_rights
        if ruleset_rights is not None:
            self.ruleset_rights = ruleset_rights
        if rule_rights is not None:
            self.rule_rights = rule_rights
        if software_inventory_rights is not None:
            self.software_inventory_rights = software_inventory_rights

    @property
    def drift_rights(self):
        """Gets the drift_rights of this ApplicationControlRights.  # noqa: E501

        Rights related to drift.  # noqa: E501

        :return: The drift_rights of this ApplicationControlRights.  # noqa: E501
        :rtype: DriftRights
        """
        return self._drift_rights

    @drift_rights.setter
    def drift_rights(self, drift_rights):
        """Sets the drift_rights of this ApplicationControlRights.

        Rights related to drift.  # noqa: E501

        :param drift_rights: The drift_rights of this ApplicationControlRights.  # noqa: E501
        :type: DriftRights
        """

        self._drift_rights = drift_rights

    @property
    def ruleset_rights(self):
        """Gets the ruleset_rights of this ApplicationControlRights.  # noqa: E501

        Rights related to rulesets.  # noqa: E501

        :return: The ruleset_rights of this ApplicationControlRights.  # noqa: E501
        :rtype: RulesetRights
        """
        return self._ruleset_rights

    @ruleset_rights.setter
    def ruleset_rights(self, ruleset_rights):
        """Sets the ruleset_rights of this ApplicationControlRights.

        Rights related to rulesets.  # noqa: E501

        :param ruleset_rights: The ruleset_rights of this ApplicationControlRights.  # noqa: E501
        :type: RulesetRights
        """

        self._ruleset_rights = ruleset_rights

    @property
    def rule_rights(self):
        """Gets the rule_rights of this ApplicationControlRights.  # noqa: E501

        Rights related to rules.  # noqa: E501

        :return: The rule_rights of this ApplicationControlRights.  # noqa: E501
        :rtype: RuleRights
        """
        return self._rule_rights

    @rule_rights.setter
    def rule_rights(self, rule_rights):
        """Sets the rule_rights of this ApplicationControlRights.

        Rights related to rules.  # noqa: E501

        :param rule_rights: The rule_rights of this ApplicationControlRights.  # noqa: E501
        :type: RuleRights
        """

        self._rule_rights = rule_rights

    @property
    def software_inventory_rights(self):
        """Gets the software_inventory_rights of this ApplicationControlRights.  # noqa: E501

        Rights related to software inventory.  # noqa: E501

        :return: The software_inventory_rights of this ApplicationControlRights.  # noqa: E501
        :rtype: SoftwareInventoryRights
        """
        return self._software_inventory_rights

    @software_inventory_rights.setter
    def software_inventory_rights(self, software_inventory_rights):
        """Sets the software_inventory_rights of this ApplicationControlRights.

        Rights related to software inventory.  # noqa: E501

        :param software_inventory_rights: The software_inventory_rights of this ApplicationControlRights.  # noqa: E501
        :type: SoftwareInventoryRights
        """

        self._software_inventory_rights = software_inventory_rights

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
        if issubclass(ApplicationControlRights, dict):
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
        if not isinstance(other, ApplicationControlRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

