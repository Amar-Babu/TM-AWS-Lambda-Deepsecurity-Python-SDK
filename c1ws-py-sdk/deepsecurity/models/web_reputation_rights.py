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

from deepsecurity.models.web_reputation_configuration_rights import WebReputationConfigurationRights  # noqa: F401,E501


class WebReputationRights(object):
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
        'web_reputation_configuration_rights': 'WebReputationConfigurationRights'
    }

    attribute_map = {
        'web_reputation_configuration_rights': 'webReputationConfigurationRights'
    }

    def __init__(self, web_reputation_configuration_rights=None):  # noqa: E501
        """WebReputationRights - a model defined in Swagger"""  # noqa: E501

        self._web_reputation_configuration_rights = None
        self.discriminator = None

        if web_reputation_configuration_rights is not None:
            self.web_reputation_configuration_rights = web_reputation_configuration_rights

    @property
    def web_reputation_configuration_rights(self):
        """Gets the web_reputation_configuration_rights of this WebReputationRights.  # noqa: E501

        Rights related to web reputation configurations.  # noqa: E501

        :return: The web_reputation_configuration_rights of this WebReputationRights.  # noqa: E501
        :rtype: WebReputationConfigurationRights
        """
        return self._web_reputation_configuration_rights

    @web_reputation_configuration_rights.setter
    def web_reputation_configuration_rights(self, web_reputation_configuration_rights):
        """Sets the web_reputation_configuration_rights of this WebReputationRights.

        Rights related to web reputation configurations.  # noqa: E501

        :param web_reputation_configuration_rights: The web_reputation_configuration_rights of this WebReputationRights.  # noqa: E501
        :type: WebReputationConfigurationRights
        """

        self._web_reputation_configuration_rights = web_reputation_configuration_rights

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
        if issubclass(WebReputationRights, dict):
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
        if not isinstance(other, WebReputationRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

