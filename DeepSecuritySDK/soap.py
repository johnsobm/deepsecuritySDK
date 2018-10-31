from zeep.client import Client
from requests import Session
from zeep.transports import Transport
from DeepSecurityConfig import  DeepSecurityConfig

class DeepSecuritySoap:



    def __init__(self, config):
        self._config = config
        self._soap_url = "https://{0}:{1}/webservice/Manager?WSDL".format(config.hostname, config.port)
        self._soap_factory = None
        self._soap_sID = None
        self._session = Session()
        self._session.verify = config.sslVerify
        self._soap_transport = Transport(session=self._session, timeout=630)
        self._soap_client = Client(self._soap_url, transport=self._soap_transport)
        self._soap_factory = self._soap_client.type_factory('ns0')

    def __del__(self):
        if self._soap_sID:
            self.Logout()

    def Authenticate(self):
        # Authenticate to the DSM
        if self._config.tenant:
            self._soap_sID = self._soap_client.service.authenticateTenant(username=self._config.username, password=self._config.password, tenantName=self._config.tenant)
        else:
            self._soap_sID = self._soap_client.service.authenticate(username=self._config.username, password=self._config.password)
        if self._soap_sID == None:
            print("Failed to authenticate to SOAP interface.")
        print("Sucessful authentication")
        return

    def Logout(self):
        self._soap_client.service.endSession(self._soap_sID)
        self._soap_sID = None

    def _CreateHostFilter(self, factory, groupID, hostID, securityProfileID, enumType):
        EnumHostFilter = factory.EnumHostFilterType(enumType)
        HostFilterTransport = factory.HostFilterTransport(hostGroupID=groupID, hostID=hostID,
                                                          securityProfileID=securityProfileID, type=EnumHostFilter)
        return HostFilterTransport

    def GetAllComputersFromGroup(self, groupID):
        soap_computers = []
        if self._soap_sID == None:
            self.Authenticate()

        if groupID:
            computers = self._soap_client.service.hostDetailRetrieve(
                    hostFilter=self._CreateHostFilter(self._soap_factory, groupID, None, None, "HOSTS_IN_GROUP"),
                    hostDetailLevel=self._soap_factory.EnumHostDetailLevel("HIGH"),
                    sID=self._soap_sID)
            return computers
        else:
            computers = self._soap_client.service.hostDetailRetrieve(
                hostFilter=self._CreateHostFilter(self._soap_factory, None, None, None, "HOSTS_IN_GROUP"),
                hostDetailLevel=self._soap_factory.EnumHostDetailLevel("HIGH"),
                sID=self._soap_sID)
            return computers
        return []


    def AllComputer(self, groups):
        soap_computers = []
        if self._soap_sID == None:
            self.Authenticate()
        for group in groups:
            computers = self._soap_client.service.hostDetailRetrieve(
                hostFilter=self._CreateHostFilter(self._soap_factory, group.id, None, None, "HOSTS_IN_GROUP"),
                hostDetailLevel=self._soap_factory.EnumHostDetailLevel("HIGH"),
                sID=self._soap_sID)
            if computers:
                soap_computers.extend(computers)
                dir_names = dir(computers[0])
                dic_name = computers[0].__dict__["__values__"].keys()

        # last is comuters without group
        computers = self._soap_client.service.hostDetailRetrieve(
            hostFilter=self._CreateHostFilter(self._soap_factory, None, None, None, "HOSTS_IN_GROUP"),
            hostDetailLevel=self._soap_factory.EnumHostDetailLevel("HIGH"),
            sID=self._soap_sID)
        if computers:
            soap_computers.extend(computers)

        return soap_computers



