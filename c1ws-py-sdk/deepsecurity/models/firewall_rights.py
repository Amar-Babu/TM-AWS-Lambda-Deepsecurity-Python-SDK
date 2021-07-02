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

from deepsecurity.models.context_rights import ContextRights  # noqa: F401,E501
from deepsecurity.models.firewall_rule_rights import FirewallRuleRights  # noqa: F401,E501
from deepsecurity.models.mac_list_rights import MacListRights  # noqa: F401,E501
from deepsecurity.models.stateful_configuration_rights import StatefulConfigurationRights  # noqa: F401,E501


class FirewallRights(object):
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
        'context_rights': 'ContextRights',
        'firewall_rule_rights': 'FirewallRuleRights',
        'stateful_configuration_rights': 'StatefulConfigurationRights',
        'mac_list_rights': 'MacListRights'
    }

    attribute_map = {
        'context_rights': 'contextRights',
        'firewall_rule_rights': 'firewallRuleRights',
        'stateful_configuration_rights': 'statefulConfigurationRights',
        'mac_list_rights': 'macListRights'
    }

    def __init__(self, context_rights=None, firewall_rule_rights=None, stateful_configuration_rights=None, mac_list_rights=None):  # noqa: E501
        """FirewallRights - a model defined in Swagger"""  # noqa: E501

        self._context_rights = None
        self._firewall_rule_rights = None
        self._stateful_configuration_rights = None
        self._mac_list_rights = None
        self.discriminator = None

        if context_rights is not None:
            self.context_rights = context_rights
        if firewall_rule_rights is not None:
            self.firewall_rule_rights = firewall_rule_rights
        if stateful_configuration_rights is not None:
            self.stateful_configuration_rights = stateful_configuration_rights
        if mac_list_rights is not None:
            self.mac_list_rights = mac_list_rights

    @property
    def context_rights(self):
        """Gets the context_rights of this FirewallRights.  # noqa: E501

        Rights related to contexts.  # noqa: E501

        :return: The context_rights of this FirewallRights.  # noqa: E501
        :rtype: ContextRights
        """
        return self._context_rights

    @context_rights.setter
    def context_rights(self, context_rights):
        """Sets the context_rights of this FirewallRights.

        Rights related to contexts.  # noqa: E501

        :param context_rights: The context_rights of this FirewallRights.  # noqa: E501
        :type: ContextRights
        """

        self._context_rights = context_rights

    @property
    def firewall_rule_rights(self):
        """Gets the firewall_rule_rights of this FirewallRights.  # noqa: E501

        Rights related to firewall rules.  # noqa: E501

        :return: The firewall_rule_rights of this FirewallRights.  # noqa: E501
        :rtype: FirewallRuleRights
        """
        return self._firewall_rule_rights

    @firewall_rule_rights.setter
    def firewall_rule_rights(self, firewall_rule_rights):
        """Sets the firewall_rule_rights of this FirewallRights.

        Rights related to firewall rules.  # noqa: E501

        :param firewall_rule_rights: The firewall_rule_rights of this FirewallRights.  # noqa: E501
        :type: FirewallRuleRights
        """

        self._firewall_rule_rights = firewall_rule_rights

    @property
    def stateful_configuration_rights(self):
        """Gets the stateful_configuration_rights of this FirewallRights.  # noqa: E501

        Rights related to stateful configurations.  # noqa: E501

        :return: The stateful_configuration_rights of this FirewallRights.  # noqa: E501
        :rtype: StatefulConfigurationRights
        """
        return self._stateful_configuration_rights

    @stateful_configuration_rights.setter
    def stateful_configuration_rights(self, stateful_configuration_rights):
        """Sets the stateful_configuration_rights of this FirewallRights.

        Rights related to stateful configurations.  # noqa: E501

        :param stateful_configuration_rights: The stateful_configuration_rights of this FirewallRights.  # noqa: E501
        :type: StatefulConfigurationRights
        """

        self._stateful_configuration_rights = stateful_configuration_rights

    @property
    def mac_list_rights(self):
        """Gets the mac_list_rights of this FirewallRights.  # noqa: E501


        :return: The mac_list_rights of this FirewallRights.  # noqa: E501
        :rtype: MacListRights
        """
        return self._mac_list_rights

    @mac_list_rights.setter
    def mac_list_rights(self, mac_list_rights):
        """Sets the mac_list_rights of this FirewallRights.


        :param mac_list_rights: The mac_list_rights of this FirewallRights.  # noqa: E501
        :type: MacListRights
        """

        self._mac_list_rights = mac_list_rights

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
        if issubclass(FirewallRights, dict):
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
        if not isinstance(other, FirewallRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
