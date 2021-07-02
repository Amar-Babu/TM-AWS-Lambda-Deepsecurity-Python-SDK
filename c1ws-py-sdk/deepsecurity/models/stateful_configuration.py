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


class StatefulConfiguration(object):
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
        'name': 'str',
        'description': 'str',
        'deny_fragmented_packets_enabled': 'bool',
        'deny_packets_containing_cwr_or_ece_enabled': 'bool',
        'max_incoming_connections': 'int',
        'max_outgoing_connections': 'int',
        'max_half_open_connections': 'int',
        'tcpstateful_inspection_enabled': 'bool',
        'tcpstateful_logging_enabled': 'bool',
        'udpstateful_inspection_enabled': 'bool',
        'udpstateful_logging_enabled': 'bool',
        'icmpstateful_inspection_enabled': 'bool',
        'icmpstateful_logging_enabled': 'bool',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'description': 'description',
        'deny_fragmented_packets_enabled': 'denyFragmentedPacketsEnabled',
        'deny_packets_containing_cwr_or_ece_enabled': 'denyPacketsContainingCwrOrEceEnabled',
        'max_incoming_connections': 'maxIncomingConnections',
        'max_outgoing_connections': 'maxOutgoingConnections',
        'max_half_open_connections': 'maxHalfOpenConnections',
        'tcpstateful_inspection_enabled': 'tcpstatefulInspectionEnabled',
        'tcpstateful_logging_enabled': 'tcpstatefulLoggingEnabled',
        'udpstateful_inspection_enabled': 'udpstatefulInspectionEnabled',
        'udpstateful_logging_enabled': 'udpstatefulLoggingEnabled',
        'icmpstateful_inspection_enabled': 'icmpstatefulInspectionEnabled',
        'icmpstateful_logging_enabled': 'icmpstatefulLoggingEnabled',
        'id': 'ID'
    }

    def __init__(self, name=None, description=None, deny_fragmented_packets_enabled=None, deny_packets_containing_cwr_or_ece_enabled=None, max_incoming_connections=None, max_outgoing_connections=None, max_half_open_connections=None, tcpstateful_inspection_enabled=None, tcpstateful_logging_enabled=None, udpstateful_inspection_enabled=None, udpstateful_logging_enabled=None, icmpstateful_inspection_enabled=None, icmpstateful_logging_enabled=None, id=None):  # noqa: E501
        """StatefulConfiguration - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._description = None
        self._deny_fragmented_packets_enabled = None
        self._deny_packets_containing_cwr_or_ece_enabled = None
        self._max_incoming_connections = None
        self._max_outgoing_connections = None
        self._max_half_open_connections = None
        self._tcpstateful_inspection_enabled = None
        self._tcpstateful_logging_enabled = None
        self._udpstateful_inspection_enabled = None
        self._udpstateful_logging_enabled = None
        self._icmpstateful_inspection_enabled = None
        self._icmpstateful_logging_enabled = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if deny_fragmented_packets_enabled is not None:
            self.deny_fragmented_packets_enabled = deny_fragmented_packets_enabled
        if deny_packets_containing_cwr_or_ece_enabled is not None:
            self.deny_packets_containing_cwr_or_ece_enabled = deny_packets_containing_cwr_or_ece_enabled
        if max_incoming_connections is not None:
            self.max_incoming_connections = max_incoming_connections
        if max_outgoing_connections is not None:
            self.max_outgoing_connections = max_outgoing_connections
        if max_half_open_connections is not None:
            self.max_half_open_connections = max_half_open_connections
        if tcpstateful_inspection_enabled is not None:
            self.tcpstateful_inspection_enabled = tcpstateful_inspection_enabled
        if tcpstateful_logging_enabled is not None:
            self.tcpstateful_logging_enabled = tcpstateful_logging_enabled
        if udpstateful_inspection_enabled is not None:
            self.udpstateful_inspection_enabled = udpstateful_inspection_enabled
        if udpstateful_logging_enabled is not None:
            self.udpstateful_logging_enabled = udpstateful_logging_enabled
        if icmpstateful_inspection_enabled is not None:
            self.icmpstateful_inspection_enabled = icmpstateful_inspection_enabled
        if icmpstateful_logging_enabled is not None:
            self.icmpstateful_logging_enabled = icmpstateful_logging_enabled
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this StatefulConfiguration.  # noqa: E501

        Name of the stateful configuration. Searchable as String.  # noqa: E501

        :return: The name of this StatefulConfiguration.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this StatefulConfiguration.

        Name of the stateful configuration. Searchable as String.  # noqa: E501

        :param name: The name of this StatefulConfiguration.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def description(self):
        """Gets the description of this StatefulConfiguration.  # noqa: E501

        Description of the stateful configuration. Searchable as String.  # noqa: E501

        :return: The description of this StatefulConfiguration.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this StatefulConfiguration.

        Description of the stateful configuration. Searchable as String.  # noqa: E501

        :param description: The description of this StatefulConfiguration.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def deny_fragmented_packets_enabled(self):
        """Gets the deny_fragmented_packets_enabled of this StatefulConfiguration.  # noqa: E501

        Controls if fragmented packets are denied. Set to true to deny fragmented packets. Searchable as Boolean.  # noqa: E501

        :return: The deny_fragmented_packets_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._deny_fragmented_packets_enabled

    @deny_fragmented_packets_enabled.setter
    def deny_fragmented_packets_enabled(self, deny_fragmented_packets_enabled):
        """Sets the deny_fragmented_packets_enabled of this StatefulConfiguration.

        Controls if fragmented packets are denied. Set to true to deny fragmented packets. Searchable as Boolean.  # noqa: E501

        :param deny_fragmented_packets_enabled: The deny_fragmented_packets_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._deny_fragmented_packets_enabled = deny_fragmented_packets_enabled

    @property
    def deny_packets_containing_cwr_or_ece_enabled(self):
        """Gets the deny_packets_containing_cwr_or_ece_enabled of this StatefulConfiguration.  # noqa: E501

        Controls if TCP CWR, ECE flags are denied. Set to true to enable CWR or ECE flags. Searchable as Boolean.  # noqa: E501

        :return: The deny_packets_containing_cwr_or_ece_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._deny_packets_containing_cwr_or_ece_enabled

    @deny_packets_containing_cwr_or_ece_enabled.setter
    def deny_packets_containing_cwr_or_ece_enabled(self, deny_packets_containing_cwr_or_ece_enabled):
        """Sets the deny_packets_containing_cwr_or_ece_enabled of this StatefulConfiguration.

        Controls if TCP CWR, ECE flags are denied. Set to true to enable CWR or ECE flags. Searchable as Boolean.  # noqa: E501

        :param deny_packets_containing_cwr_or_ece_enabled: The deny_packets_containing_cwr_or_ece_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._deny_packets_containing_cwr_or_ece_enabled = deny_packets_containing_cwr_or_ece_enabled

    @property
    def max_incoming_connections(self):
        """Gets the max_incoming_connections of this StatefulConfiguration.  # noqa: E501

        Maximum allowed incoming connections. Searchable as Numeric.  # noqa: E501

        :return: The max_incoming_connections of this StatefulConfiguration.  # noqa: E501
        :rtype: int
        """
        return self._max_incoming_connections

    @max_incoming_connections.setter
    def max_incoming_connections(self, max_incoming_connections):
        """Sets the max_incoming_connections of this StatefulConfiguration.

        Maximum allowed incoming connections. Searchable as Numeric.  # noqa: E501

        :param max_incoming_connections: The max_incoming_connections of this StatefulConfiguration.  # noqa: E501
        :type: int
        """

        self._max_incoming_connections = max_incoming_connections

    @property
    def max_outgoing_connections(self):
        """Gets the max_outgoing_connections of this StatefulConfiguration.  # noqa: E501

        Maximum allowed outgoing connections. Searchable as Numeric.  # noqa: E501

        :return: The max_outgoing_connections of this StatefulConfiguration.  # noqa: E501
        :rtype: int
        """
        return self._max_outgoing_connections

    @max_outgoing_connections.setter
    def max_outgoing_connections(self, max_outgoing_connections):
        """Sets the max_outgoing_connections of this StatefulConfiguration.

        Maximum allowed outgoing connections. Searchable as Numeric.  # noqa: E501

        :param max_outgoing_connections: The max_outgoing_connections of this StatefulConfiguration.  # noqa: E501
        :type: int
        """

        self._max_outgoing_connections = max_outgoing_connections

    @property
    def max_half_open_connections(self):
        """Gets the max_half_open_connections of this StatefulConfiguration.  # noqa: E501

        Maximum allowed half open connections. Searchable as Numeric.  # noqa: E501

        :return: The max_half_open_connections of this StatefulConfiguration.  # noqa: E501
        :rtype: int
        """
        return self._max_half_open_connections

    @max_half_open_connections.setter
    def max_half_open_connections(self, max_half_open_connections):
        """Sets the max_half_open_connections of this StatefulConfiguration.

        Maximum allowed half open connections. Searchable as Numeric.  # noqa: E501

        :param max_half_open_connections: The max_half_open_connections of this StatefulConfiguration.  # noqa: E501
        :type: int
        """

        self._max_half_open_connections = max_half_open_connections

    @property
    def tcpstateful_inspection_enabled(self):
        """Gets the tcpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The tcpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._tcpstateful_inspection_enabled

    @tcpstateful_inspection_enabled.setter
    def tcpstateful_inspection_enabled(self, tcpstateful_inspection_enabled):
        """Sets the tcpstateful_inspection_enabled of this StatefulConfiguration.


        :param tcpstateful_inspection_enabled: The tcpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._tcpstateful_inspection_enabled = tcpstateful_inspection_enabled

    @property
    def tcpstateful_logging_enabled(self):
        """Gets the tcpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The tcpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._tcpstateful_logging_enabled

    @tcpstateful_logging_enabled.setter
    def tcpstateful_logging_enabled(self, tcpstateful_logging_enabled):
        """Sets the tcpstateful_logging_enabled of this StatefulConfiguration.


        :param tcpstateful_logging_enabled: The tcpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._tcpstateful_logging_enabled = tcpstateful_logging_enabled

    @property
    def udpstateful_inspection_enabled(self):
        """Gets the udpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The udpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._udpstateful_inspection_enabled

    @udpstateful_inspection_enabled.setter
    def udpstateful_inspection_enabled(self, udpstateful_inspection_enabled):
        """Sets the udpstateful_inspection_enabled of this StatefulConfiguration.


        :param udpstateful_inspection_enabled: The udpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._udpstateful_inspection_enabled = udpstateful_inspection_enabled

    @property
    def udpstateful_logging_enabled(self):
        """Gets the udpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The udpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._udpstateful_logging_enabled

    @udpstateful_logging_enabled.setter
    def udpstateful_logging_enabled(self, udpstateful_logging_enabled):
        """Sets the udpstateful_logging_enabled of this StatefulConfiguration.


        :param udpstateful_logging_enabled: The udpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._udpstateful_logging_enabled = udpstateful_logging_enabled

    @property
    def icmpstateful_inspection_enabled(self):
        """Gets the icmpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The icmpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._icmpstateful_inspection_enabled

    @icmpstateful_inspection_enabled.setter
    def icmpstateful_inspection_enabled(self, icmpstateful_inspection_enabled):
        """Sets the icmpstateful_inspection_enabled of this StatefulConfiguration.


        :param icmpstateful_inspection_enabled: The icmpstateful_inspection_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._icmpstateful_inspection_enabled = icmpstateful_inspection_enabled

    @property
    def icmpstateful_logging_enabled(self):
        """Gets the icmpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501


        :return: The icmpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :rtype: bool
        """
        return self._icmpstateful_logging_enabled

    @icmpstateful_logging_enabled.setter
    def icmpstateful_logging_enabled(self, icmpstateful_logging_enabled):
        """Sets the icmpstateful_logging_enabled of this StatefulConfiguration.


        :param icmpstateful_logging_enabled: The icmpstateful_logging_enabled of this StatefulConfiguration.  # noqa: E501
        :type: bool
        """

        self._icmpstateful_logging_enabled = icmpstateful_logging_enabled

    @property
    def id(self):
        """Gets the id of this StatefulConfiguration.  # noqa: E501

        ID of the stateful configuration. Searchable as ID.  # noqa: E501

        :return: The id of this StatefulConfiguration.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this StatefulConfiguration.

        ID of the stateful configuration. Searchable as ID.  # noqa: E501

        :param id: The id of this StatefulConfiguration.  # noqa: E501
        :type: int
        """

        self._id = id

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
        if issubclass(StatefulConfiguration, dict):
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
        if not isinstance(other, StatefulConfiguration):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

