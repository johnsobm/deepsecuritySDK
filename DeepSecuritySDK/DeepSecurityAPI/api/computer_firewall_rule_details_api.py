# coding: utf-8

"""
    Trend Micro Deep Security API

    Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 11.2.225
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from DeepSecurityAPI.api_client import ApiClient


class ComputerFirewallRuleDetailsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def describe_firewall_rule_on_computer(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Describe a firewall rule  # noqa: E501

        Describe a firewall rule including computer-level overrides. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.describeFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.describeFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.describe_firewall_rule_on_computer(computer_id, firewall_rule_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async'):
            return self.describe_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_firewall_rule_on_computer_with_http_info(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Describe a firewall rule  # noqa: E501

        Describe a firewall rule including computer-level overrides. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.describeFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.describeFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.describe_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'firewall_rule_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_firewall_rule_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `describe_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule_id' is set
        if ('firewall_rule_id' not in params or
                params['firewall_rule_id'] is None):
            raise ValueError("Missing the required parameter `firewall_rule_id` when calling `describe_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_firewall_rule_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', params['computer_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `describe_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'firewall_rule_id' in params and not re.search('\\d+', params['firewall_rule_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `firewall_rule_id` when calling `describe_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501
        if 'firewall_rule_id' in params:
            path_params['firewallRuleID'] = params['firewall_rule_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/rules/{firewallRuleID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallRule',  # noqa: E501
            auth_settings=auth_settings,
            async=params.get('async'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_firewall_rules_on_computer(self, computer_id, api_version, **kwargs):  # noqa: E501
        """List firewall rules  # noqa: E501

        Lists all firewall rules assigned to a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.listFirewallRulesOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.listFirewallRulesOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.list_firewall_rules_on_computer(computer_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only rules assigned to the current computer.
        :return: FirewallRules
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async'):
            return self.list_firewall_rules_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_firewall_rules_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
            return data

    def list_firewall_rules_on_computer_with_http_info(self, computer_id, api_version, **kwargs):  # noqa: E501
        """List firewall rules  # noqa: E501

        Lists all firewall rules assigned to a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.listFirewallRulesOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.listFirewallRulesOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.list_firewall_rules_on_computer_with_http_info(computer_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only rules assigned to the current computer.
        :return: FirewallRules
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_firewall_rules_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `list_firewall_rules_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_firewall_rules_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', params['computer_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `list_firewall_rules_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/rules', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallRules',  # noqa: E501
            auth_settings=auth_settings,
            async=params.get('async'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def modify_firewall_rule_on_computer(self, computer_id, firewall_rule_id, firewall_rule, api_version, **kwargs):  # noqa: E501
        """Modify a firewall rule  # noqa: E501

        Modify a firewall rule assigned to a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.modifyFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.modifyFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.modify_firewall_rule_on_computer(computer_id, firewall_rule_id, firewall_rule, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to modify. (required)
        :param FirewallRule firewall_rule: The settings of the firewall rule to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async'):
            return self.modify_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, firewall_rule, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.modify_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, firewall_rule, api_version, **kwargs)  # noqa: E501
            return data

    def modify_firewall_rule_on_computer_with_http_info(self, computer_id, firewall_rule_id, firewall_rule, api_version, **kwargs):  # noqa: E501
        """Modify a firewall rule  # noqa: E501

        Modify a firewall rule assigned to a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.modifyFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.modifyFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.modify_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, firewall_rule, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to modify. (required)
        :param FirewallRule firewall_rule: The settings of the firewall rule to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'firewall_rule_id', 'firewall_rule', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method modify_firewall_rule_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `modify_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule_id' is set
        if ('firewall_rule_id' not in params or
                params['firewall_rule_id'] is None):
            raise ValueError("Missing the required parameter `firewall_rule_id` when calling `modify_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule' is set
        if ('firewall_rule' not in params or
                params['firewall_rule'] is None):
            raise ValueError("Missing the required parameter `firewall_rule` when calling `modify_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `modify_firewall_rule_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', params['computer_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `modify_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'firewall_rule_id' in params and not re.search('\\d+', params['firewall_rule_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `firewall_rule_id` when calling `modify_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501
        if 'firewall_rule_id' in params:
            path_params['firewallRuleID'] = params['firewall_rule_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'firewall_rule' in params:
            body_params = params['firewall_rule']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/rules/{firewallRuleID}', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallRule',  # noqa: E501
            auth_settings=auth_settings,
            async=params.get('async'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def reset_firewall_rule_on_computer(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Reset firewall rule overrides  # noqa: E501

        Remove all overrides for a firewall rule from a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.resetFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.resetFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.reset_firewall_rule_on_computer(computer_id, firewall_rule_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to reset. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async'):
            return self.reset_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.reset_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
            return data

    def reset_firewall_rule_on_computer_with_http_info(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Reset firewall rule overrides  # noqa: E501

        Remove all overrides for a firewall rule from a computer. <header class=\"param-type\">Related SDK Methods:</header><div _ngcontent-c12=\"\" class=\"params-wrap\"><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">Java</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.resetFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div><div _ngcontent-c12=\"\" class=\"param\">  <div _ngcontent-c12=\"\" class=\"param-name\">    <span _ngcontent-c12=\"\" class=\"param-name-wrap\">JavaScript</span>  </div>  <div _ngcontent-c12=\"\" class=\"param-info\">    <div></div>    <div _ngcontent-c12=\"\" class=\"param-description\">      <span class=\"redoc-markdown-block\"><p>ComputerFirewallRuleDetailsApi.resetFirewallRuleOnComputer([param1, param2, ...])</p></span>    </div>  </div></div></div>  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async=True
        >>> thread = api.reset_firewall_rule_on_computer_with_http_info(computer_id, firewall_rule_id, api_version, async=True)
        >>> result = thread.get()

        :param async bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to reset. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Show only overrides defined for the current computer.
        :return: FirewallRule
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'firewall_rule_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method reset_firewall_rule_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `reset_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule_id' is set
        if ('firewall_rule_id' not in params or
                params['firewall_rule_id'] is None):
            raise ValueError("Missing the required parameter `firewall_rule_id` when calling `reset_firewall_rule_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `reset_firewall_rule_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', params['computer_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `reset_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'firewall_rule_id' in params and not re.search('\\d+', params['firewall_rule_id']):  # noqa: E501
            raise ValueError("Invalid value for parameter `firewall_rule_id` when calling `reset_firewall_rule_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501
        if 'firewall_rule_id' in params:
            path_params['firewallRuleID'] = params['firewall_rule_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/rules/{firewallRuleID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallRule',  # noqa: E501
            auth_settings=auth_settings,
            async=params.get('async'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
