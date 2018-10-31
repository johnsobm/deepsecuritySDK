
from soap import DeepSecuritySoap
from rest import DeepSecurityRestApi
import datetime
from threading import Thread
from threading import Lock
import copy
import pandas as pd

class DeepSecurity:
    def __init__(self, config):
        if config.username:
            self._soap=DeepSecuritySoap(config)
        else:
            self._soap=None
        if config.apiKey:
            self._rest=DeepSecurityRestApi(config)

        self._lock = Lock()
        self._RestComputers = []
        self._soapComputers = []
        self._Groups = None


    def Cleanup(self):
        self._soap.Logout()

    def _computers_tread(self, groupID):
        computersReturn = self._rest.GetAllComputersFromGroup(groupID=groupID)
        self._lock.acquire()
        self._RestComputers.extend(computersReturn)
        self._lock.release()

        return

    def _soap_computers_thread(self, groupList):
        if self._soap == None:
            return
        self._soapComputers = self._soap.AllComputer(groupList)
        return

    def GetAllComputers(self, threadCount=16):
        threads = []
        nonGroupcomputersThread = Thread(target=self._computers_tread, args=(None,))
        nonGroupcomputersThread.start()

        if self._Groups is None:
            groups_rest_object = self._rest.AllGroups()
            self._Groups = groups_rest_object.computer_groups

        soapThreead = Thread(target=self._soap_computers_thread, args=(self._Groups,))
        soapThreead.start()

        allGroups = copy.copy( self._Groups)
        count = len(self._Groups)
        while (count > 0 and threadCount < len(allGroups)):
            for i in range(threadCount):
                group = allGroups.pop()
                threads.append(Thread(target=self._computers_tread, args=(group.id,)))
            for i in range(threadCount):
                threads[i].start()
            for i in range(threadCount):
                threads[i].join()
            threads = []
            count -= threadCount

        for group in allGroups:
            self._computers_tread(group.id)

        # Last get the computers with no group
        nonGroupcomputersThread.join()
        soapThreead.join()

        return

    def _GetSoapComputer(self, computer):
        for soapComputer in self._soapComputers:
            if computer.id == soapComputer.ID:
                return soapComputer

    def BuildReportData(self):
        self.GetAllComputers()
        return self._buildDataFrameStaticlly()

    def Test(self):
        groups = self._rest.AllGroups()
        for group in groups.computer_groups:
            self._RestComputers = self._rest.GetAllComputersFromGroup(group.id)
            self._soapComputers = self._soap.GetAllComputersFromGroup(group.id)
            if len(self._RestComputers) > 0:
                return self._buildDataFrameStaticlly()

    def _NOT_READY_BuildPandasObject(self):
        columes = []
        rest_columes = []
        soap_columes = []
        dir_names = dir(self._RestComputers[0])
        for name in dir_names:
            if not name.startswith("_")\
                    and (name != "swagger_types")\
                    and (name != "to_dict")\
                    and (name != "to_str")\
                    and (name != "discriminator")\
                    and (name != "attribute_map"):
                columes.append(name)
                rest_columes.append(name)
        if self._soapComputers:
            dir_names = dir(self._soapComputers[0])
            for name in dir_names:
                if not name.startswith("_"):
                    columes.append(name)
                    soap_columes.append(name)

        print "Rest Columns: \n"
        print (rest_columes)
        print "\nSoap Columns: \n"
        print (soap_columes)

        #df = pd.DataFrame(columns=columes)
        df = None

        for restComputer in self._RestComputers:
            soapComputer = self._GetSoapComputer(restComputer)
            row = {}
            for colName in rest_columes:
                try:
                    row[colName] = [restComputer.__dict__["_{0}".format(colName)]]
                except Exception as err:
                    print "Build DataFrame, adding RESTful computer data {0} failed.\n".format(colName)
            for colName in soap_columes:
                try:
                    row[colName] = [soapComputer.__dict__["__values__"][colName]]
                except Exception as err:
                    print "Build DataFrame, adding SOAP computer data {0} failed.\n".format(colName)
            #new_df = pd.DataFrame.from_dict(row, orient='columns')
            new_df = pd.DataFrame.from_dict(row)
            new_df.set_index('id')
            if df is None:
                df = new_df
            else:
                df = pd.concat([new_df, df])
            #new_df = pd.DataFrame(row)
            #df.append(new_df, ignore_index=True)
        return df

    def _convertTimeStamp(self, serverTime):
        if serverTime:
            t =  datetime.datetime.fromtimestamp(serverTime / 1000).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            return t
        return "1970-01-01T00:00:00.000Z"

    def _buildDataFrameStaticlly(self):
        df = None

        for restComputer in self._RestComputers:
            soapComputer = self._GetSoapComputer(restComputer)
            row = {}
            row['agent_finger_print'] = [restComputer.agent_finger_print]
            row['agent_version'] = [restComputer.agent_version]

            row['anti_malware_state'] = [restComputer.anti_malware.state]
            row['anti_malware_scheduled_scan_configuration_id'] = [restComputer.anti_malware.scheduled_scan_configuration_id]
            row['anti_malware_real_time_scan_schedule_id'] = [restComputer.anti_malware.real_time_scan_schedule_id]
            row['anti_malware_real_time_scan_configuration_id'] = [restComputer.anti_malware.real_time_scan_configuration_id]
            row['anti_malware_manual_scan_configuration_id'] = [restComputer.anti_malware.manual_scan_configuration_id]


            row['appliance_finger_print'] = [restComputer.appliance_finger_print]
            row['application_control_state'] = [restComputer.application_control.state]
            row['application_control_ruleset_id'] = [restComputer.application_control.ruleset_id]
            row['application_control_block_unrecognized'] = [restComputer.application_control.block_unrecognized]

            if restComputer.asset_importance_id:
                row['asset_importance_id'] = [restComputer.asset_importance_id]
            if restComputer.azure_arm_virtual_machine_summary:
                row['azure_arm_virtual_machine_summary'] = [restComputer.azure_arm_virtual_machine_summary]
            if restComputer.azure_vm_virtual_machine_summary:
                row['azure_vm_virtual_machine_summary'] = [restComputer.azure_vm_virtual_machine_summary]
            row['bios_uuid'] = [restComputer.bios_uuid]
            row['computer_settings'] = [restComputer.computer_settings]
            row['description'] = [restComputer.description]
            row['display_name'] = [restComputer.display_name]
            if restComputer.ec2_virtual_machine_summary:
                row['ec2_virtual_machine_summary_ami_id'] = [restComputer.ec2_virtual_machine_summary.ami_id]
                row['ec2_virtual_machine_summary_availability_zone'] = [restComputer.ec2_virtual_machine_summary.availability_zone]
                row['ec2_virtual_machine_summary_cloud_provider'] = [restComputer.ec2_virtual_machine_summary.cloud_provider]
                row['ec2_virtual_machine_summary_dns_name'] = [restComputer.ec2_virtual_machine_summary.dns_name]
                row['ec2_virtual_machine_summary_instance_id'] = [restComputer.ec2_virtual_machine_summary.instance_id]
                if restComputer.ec2_virtual_machine_summary.metadata:
                    for keyvalue in restComputer.ec2_virtual_machine_summary.metadata:
                        row['aws_tag:{0}'.format(keyvalue.name)] = [keyvalue.value]
                row['ec2_virtual_machine_summary_metadata'] = [restComputer.ec2_virtual_machine_summary.metadata]
                row['ec2_virtual_machine_summary_operating_system'] = [restComputer.ec2_virtual_machine_summary.operating_system]
                row['ec2_virtual_machine_summary_private_ip_address'] = [restComputer.ec2_virtual_machine_summary.private_ip_address]
                row['ec2_virtual_machine_summary_public_ip_address'] = [restComputer.ec2_virtual_machine_summary.public_ip_address]
                row['ec2_virtual_machine_summary_security_groups'] = [restComputer.ec2_virtual_machine_summary.security_groups]
                row['ec2_virtual_machine_summary_state'] = [restComputer.ec2_virtual_machine_summary.state]
                row['ec2_virtual_machine_summary_type'] = [restComputer.ec2_virtual_machine_summary.type]
                row['ec2_virtual_machine_summary_virtualization_type'] = [restComputer.ec2_virtual_machine_summary.virtualization_type]
            if restComputer.esx_summary:
                row['esx_summary_manufacturer'] = [restComputer.esx_summary.manufacturer]
                row['esx_summary_model'] = [restComputer.esx_summary.model]
                row['esx_summary_processors'] = [restComputer.esx_summary.processors]
                row['esx_summary_processorType'] = [restComputer.esx_summary.processor_type]
                row['esx_summary_state'] = [restComputer.esx_summary.state]
                row['esx_summary_virtualMachines'] = [restComputer.esx_summary.virtual_machines]
                row['esx_summary_customAttributes'] = restComputer.esx_summary.custom_attributes
                row['esx_summary_vMotionEnabled'] = [restComputer.esx_summary.v_motion_enabled]
                row['esx_summary_TPMEnabled'] = [restComputer.esx_summary.tpmenabled]
                row['esx_summary_TPMAlertsEnabled'] = [restComputer.esx_summary.tpmalerts_enabled]
                row['esx_summary_TPMHasData'] = [restComputer.esx_summary.tpmhas_data]
                row['esx_summary_TPMLastChecked'] = [restComputer.esx_summary.tpmlast_checked]

            if restComputer.firewall:
                row['firewall_state'] = [restComputer.firewall.state]
                row['firewall_global_stateful_configuration_id'] = [restComputer.firewall.global_stateful_configuration_id]
                row['firewall_rule_i_ds'] = [restComputer.firewall.rule_i_ds]
            if restComputer.firewall.stateful_configuration_assignments:
                row['firewall_stateful_configuration_assignments'] = [restComputer.firewall.stateful_configuration_assignments]

            row['group_id'] = [restComputer.group_id]
            row['host_name'] = [restComputer.host_name]
            row['id'] = [restComputer.id]

            row['integrity_monitoring_state'] = [restComputer.integrity_monitoring.state]
            if restComputer.integrity_monitoring.rule_i_ds:
                row['integrity_monitoring_rules'] = [restComputer.integrity_monitoring.rule_i_ds]

            if restComputer.interfaces:
                row['interfaces'] = [restComputer.interfaces.interfaces]

            if restComputer.intrusion_prevention:
                row['intrusion_prevention_state'] = [restComputer.intrusion_prevention.state]
                row['intrusion_prevention_rule_i_ds'] = [restComputer.intrusion_prevention.rule_i_ds]

            row['last_agent_communication'] = [self._convertTimeStamp(restComputer.last_agent_communication)]
            row['last_ip_used'] = [restComputer.last_ip_used]
            row['last_send_policy_request'] = [self._convertTimeStamp(restComputer.last_send_policy_request)]
            row['last_send_policy_success'] = [self._convertTimeStamp(restComputer.last_send_policy_success)]
            if restComputer.log_inspection:
                row['log_inspection_state'] = [restComputer.log_inspection.state]
            if restComputer.no_connector_virtual_machine_summary:
                row['no_connector_virtual_machine_summary_accountID'] = [restComputer.no_connector_virtual_machine_summary.account_id]
                row['no_connector_virtual_machine_summary_directoryID'] = [restComputer.no_connector_virtual_machine_summary.directory_id]
                row['no_connector_virtual_machine_summary_userName'] = [restComputer.no_connector_virtual_machine_summary.user_name]
                row['no_connector_virtual_machine_summary_instanceID'] = [restComputer.no_connector_virtual_machine_summary.instance_id]
                row['no_connector_virtual_machine_summary_region'] = [restComputer.no_connector_virtual_machine_summary.region]
            row['platform'] = [restComputer.platform]
            row['policy_id'] = [restComputer.policy_id]
            row['relay_list_id'] = [restComputer.relay_list_id]
            if restComputer.sap:
                row['sap_state'] = [restComputer.sap.state]
            if restComputer.vmware_vm_virtual_machine_summary:
                row['vmware_vm_virtual_machine_summary_cloudProvider'] = [restComputer.vmware_vm_virtual_machine_summary.cloud_provider]
                row['vmware_vm_virtual_machine_summary_operatingSystem'] = [restComputer.vmware_vm_virtual_machine_summary.operating_system]
                row['vmware_vm_virtual_machine_summary_instanceID'] = [restComputer.vmware_vm_virtual_machine_summary.instance_id]
                row['vmware_vm_virtual_machine_summary_type'] = [restComputer.vmware_vm_virtual_machine_summary.type]
                row['vmware_vm_virtual_machine_summary_state'] = [restComputer.vmware_vm_virtual_machine_summary.state]
                row['vmware_vm_virtual_machine_summary_memory'] = [restComputer.vmware_vm_virtual_machine_summary.memory]
                row['vmware_vm_virtual_machine_summary_vmwareTools'] = [restComputer.vmware_vm_virtual_machine_summary.vmware_tools]
                row['vmware_vm_virtual_machine_summary_biosUUID'] = [restComputer.vmware_vm_virtual_machine_summary.bios_uuid]
                row['vmware_vm_virtual_machine_summary_notes'] = restComputer.vmware_vm_virtual_machine_summary.notes
                row['vmware_vm_virtual_machine_summary_CPU'] = [restComputer.vmware_vm_virtual_machine_summary.cpu]
                row['vmware_vm_virtual_machine_summary_vCenterUUID'] = [restComputer.vmware_vm_virtual_machine_summary.v_center_uuid]
                row['vmware_vm_virtual_machine_summary_NSXSecurityGroups'] = restComputer.vmware_vm_virtual_machine_summary.nsxsecurity_groups
                row['vmware_vm_virtual_machine_summary_IPAddress'] = [restComputer.vmware_vm_virtual_machine_summary.ipaddress]
                row['vmware_vm_virtual_machine_summary_DNSName'] = [restComputer.vmware_vm_virtual_machine_summary.dnsname]

            if restComputer.web_reputation:
                row['web_reputation_state'] = [restComputer.web_reputation.state]
            if restComputer.workspace_virtual_machine_summary:
                row['workspace_virtual_machine_summary_cloudProvider'] = [restComputer.workspace_virtual_machine_summary.cloud_provider]
                row['workspace_virtual_machine_summary_workspaceDirectory'] = [restComputer.workspace_virtual_machine_summary.workspace_directory]
                row['workspace_virtual_machine_summary_userName'] = [restComputer.workspace_virtual_machine_summary.user_name]
                row['workspace_virtual_machine_summary_workspaceID'] = [restComputer.workspace_virtual_machine_summary.workspace_id]
                row['workspace_virtual_machine_summary_bundleID'] = [restComputer.workspace_virtual_machine_summary.bundle_id]
                row['workspace_virtual_machine_summary_workspaceHardware'] = [restComputer.workspace_virtual_machine_summary.workspace_hardware]
                row['workspace_virtual_machine_summary_state'] = [restComputer.workspace_virtual_machine_summary.state]
                row['workspace_virtual_machine_summary_metadata'] = [restComputer.workspace_virtual_machine_summary.metadata]
                row['workspace_virtual_machine_summary_ipaddress'] = [restComputer.workspace_virtual_machine_summary.ipaddress]
            if soapComputer:
                row['antiMalwareClassicPatternVersion'] = [soapComputer.antiMalwareClassicPatternVersion]
                row['antiMalwareEngineVersion'] = [soapComputer.antiMalwareEngineVersion]
                row['antiMalwareIntelliTrapExceptionVersion'] = [soapComputer.antiMalwareIntelliTrapExceptionVersion]
                row['antiMalwareIntelliTrapVersion'] = [soapComputer.antiMalwareIntelliTrapVersion]
                row['antiMalwareSmartScanPatternVersion'] = [soapComputer.antiMalwareSmartScanPatternVersion]
                row['antiMalwareSpywarePatternVersion'] = [soapComputer.antiMalwareSpywarePatternVersion]
                row['cloudObjectImageId'] = [soapComputer.cloudObjectImageId]
                row['cloudObjectInstanceId'] = [soapComputer.cloudObjectInstanceId]
                row['cloudObjectInternalUniqueId'] = [soapComputer.cloudObjectInternalUniqueId]
                row['cloudObjectSecurityGroupIds'] = [soapComputer.cloudObjectSecurityGroupIds]
                row['cloudObjectType'] = [soapComputer.cloudObjectType]
                row['componentKlasses'] = [soapComputer.componentKlasses.item]
                row['componentNames'] = [soapComputer.componentNames.item]
                row['componentTypes'] = [soapComputer.componentTypes.item]
                row['componentVersions'] = [soapComputer.componentVersions.item]
                row['description'] = [soapComputer.description]
                row['displayName'] = [soapComputer.displayName]
                row['external'] = [soapComputer.external]
                row['externalID'] = [soapComputer.externalID]
                row['hostGroupID'] = [soapComputer.hostGroupID]
                row['hostGroupName'] = [soapComputer.hostGroupName]
                row['hostInterfaces'] = [soapComputer.hostInterfaces]
                row['hostLight'] = [soapComputer.hostLight]
                row['hostType'] = [soapComputer.hostType]
                row['lastAnitMalwareScheduledScan'] = [soapComputer.lastAnitMalwareScheduledScan]
                row['lastAntiMalwareEvent'] = [soapComputer.lastAntiMalwareEvent]
                row['lastAntiMalwareManualScan'] = [soapComputer.lastAntiMalwareManualScan]
                row['lastDpiEvent'] = [soapComputer.lastDpiEvent]
                row['lastFirewallEvent'] = [soapComputer.lastFirewallEvent]
                row['lastIPUsed'] = [soapComputer.lastIPUsed]
                row['lastIntegrityMonitoringEvent'] = [soapComputer.lastIntegrityMonitoringEvent]
                row['lastLogInspectionEvent'] = [soapComputer.lastLogInspectionEvent]
                row['lastWebReputationEvent'] = [soapComputer.lastWebReputationEvent]
                row['light'] = [soapComputer.light]
                row['locked'] = [soapComputer.locked]
                row['name'] = [soapComputer.name]
                row['overallAntiMalwareStatus'] = [soapComputer.overallAntiMalwareStatus]
                row['overallDpiStatus'] = [soapComputer.overallDpiStatus]
                row['overallFirewallStatus'] = [soapComputer.overallFirewallStatus]
                row['overallIntegrityMonitoringStatus'] = [soapComputer.overallIntegrityMonitoringStatus]
                row['overallLastRecommendationScan'] = [soapComputer.overallLastRecommendationScan]
                row['overallLastSuccessfulCommunication'] = [soapComputer.overallLastSuccessfulCommunication]
                row['overallLastSuccessfulUpdate'] = [soapComputer.overallLastSuccessfulUpdate]
                row['overallLastUpdateRequired'] = [soapComputer.overallLastUpdateRequired]
                row['overallLogInspectionStatus'] = [soapComputer.overallLogInspectionStatus]
                row['overallStatus'] = [soapComputer.overallStatus]
                row['overallVersion'] = [soapComputer.overallVersion]
                row['overallWebReputationStatus'] = [soapComputer.overallWebReputationStatus]
                row['platform'] = [soapComputer.platform]
                row['securityProfileID'] = [soapComputer.securityProfileID]
                row['securityProfileName'] = [soapComputer.securityProfileName]
                row['virtualName'] = [soapComputer.virtualName]
                row['virtualUuid'] = [soapComputer.virtualUuid]

            new_df = pd.DataFrame.from_dict(row)
            new_df = new_df.set_index('id')
            if df is None:
                df = new_df
            else:
                df = pd.concat([new_df, df])

        return df