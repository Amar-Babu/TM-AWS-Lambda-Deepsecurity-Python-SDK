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

from deepsecurity.models.v_center_info import VCenterInfo  # noqa: F401,E501


class VCenterConnector(object):
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
        'id': 'int',
        'v_center': 'VCenterInfo'
    }

    attribute_map = {
        'id': 'id',
        'v_center': 'vCenter'
    }

    def __init__(self, id=None, v_center=None):  # noqa: E501
        """VCenterConnector - a model defined in Swagger"""  # noqa: E501

        self._id = None
        self._v_center = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if v_center is not None:
            self.v_center = v_center

    @property
    def id(self):
        """Gets the id of this VCenterConnector.  # noqa: E501

        ID number of the vCenter connector.  # noqa: E501

        :return: The id of this VCenterConnector.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this VCenterConnector.

        ID number of the vCenter connector.  # noqa: E501

        :param id: The id of this VCenterConnector.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def v_center(self):
        """Gets the v_center of this VCenterConnector.  # noqa: E501

        vCenter settings.  # noqa: E501

        :return: The v_center of this VCenterConnector.  # noqa: E501
        :rtype: VCenterInfo
        """
        return self._v_center

    @v_center.setter
    def v_center(self, v_center):
        """Sets the v_center of this VCenterConnector.

        vCenter settings.  # noqa: E501

        :param v_center: The v_center of this VCenterConnector.  # noqa: E501
        :type: VCenterInfo
        """

        self._v_center = v_center

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
        if issubclass(VCenterConnector, dict):
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
        if not isinstance(other, VCenterConnector):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
