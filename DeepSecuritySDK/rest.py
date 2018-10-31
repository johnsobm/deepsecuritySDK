
from DeepSecuritySDK import DeepSecurityAPI as dsmAPI
from DeepSecuritySDK.DeepSecurityAPI import models

class DeepSecurityRestApi:

    def __init__(self, config):
        self._config = config
        self._url = "https://{0}:{1}/api".format(self._config.hostname, self._config.port)
        self._Conf = dsmAPI.Configuration()
        self._Conf.host = self._url
        self._Conf.verify_ssl = self._config.sslVerify
        self._Conf.debug = self._config.Debug
        self._Conf.api_key = {'api-secret-key': self._config.apiKey}
        self._client = dsmAPI.ApiClient(self._Conf)
        self._computerAPI = dsmAPI.ComputersApi(self._client)
        self._policyAPI = dsmAPI.PoliciesApi(self._client)
        self._groupAPI = dsmAPI.ComputerGroupsApi(self._client)

        self._firewallAPI = dsmAPI.ComputerFirewallRuleAssignmentsApi(self._client)
        self._firewallRulesAPI = dsmAPI.FirewallRulesApi(self._client)
        self._portlistAPI = dsmAPI.PortListsApi(self._client)
        self._computerIPS_API = dsmAPI.ComputerIntrusionPreventionRuleDetailsApi(self._client)

        self._integrityAPI = dsmAPI.IntegrityMonitoringRulesApi(self._client)
        self._IPSAPI = dsmAPI.IntrusionPreventionRulesApi(self._client)
        self._LogInspectionAPI = dsmAPI.LogInspectionRulesApi(self._client)
        self._antiMalwareAPI = dsmAPI.AntiMalwareConfigurationsApi(self._client)
        self._IntegrityMonitorComputerAPI = dsmAPI.ComputerIntegrityMonitoringRuleAssignmentsRecommendationsApi(
            self._client)
        self._computerIPS = dsmAPI.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(self._client)
        self._computerLog = dsmAPI.ComputerLogInspectionRuleAssignmentsRecommendationsApi(self._client)



    def GetAllComputersFromGroup(self, groupID):
        groupComputers = []
        DoAgain = True
        ComputerIndex = 0
        Max_items = 500
        while DoAgain:
            try:
                if groupID:
                    search_by_group = models.SearchCriteria(field_name="groupID", numeric_value=groupID,
                                                                           numeric_test="equal")
                else:
                    search_by_group = models.SearchCriteria(field_name="groupID", null_test=True)

                search_by_id = models.SearchCriteria(id_value=ComputerIndex,
                                                                    id_test="greater-than-or-equal")

                searchfilter = models.SearchFilter(max_items=Max_items,
                                                                  search_criteria=[search_by_group, search_by_id],
                                                                  sort_by_object_id=True)

                computersReturn = self._computerAPI.search_computers("v1", search_filter=searchfilter).computers
                DoAgain = False
                if len(computersReturn) > 0:
                    groupComputers += computersReturn
                if len(computersReturn) == Max_items:
                    DoAgain = True
                    ComputerIndex = computersReturn[len(computersReturn) - 1].id
                    ComputerIndex = ComputerIndex + 1

            except Exception as err:
                print("Error obtaining Group {0} with error {1}".format(groupID, err))
                if err.status == 404:
                    DoAgain = False

        return groupComputers

    def AllGroups(self):
        DoAgain = True
        while DoAgain:
            try:
                allGroups = self._groupAPI.list_computer_groups("v1")
                DoAgain = False
            except Exception as err:
                print("Error obtaining Group computers ith error {0}".format(err))
        return allGroups



