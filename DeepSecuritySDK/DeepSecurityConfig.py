
class DeepSecurityConfig:

    def __init__(self):
        self.username=None
        self.password=None
        self.hostname=None
        self.apiKey=None
        self.sslVerify=True
        self.port=443
        self.tenant = None
        self.Debug = False


    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, username):
        self.__username = username

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    @property
    def hostname(self):
        return self.__hostname

    @hostname.setter
    def hostname(self, hostname):
        self.__hostname = hostname

    @property
    def apiKey(self):
        return self.__apiKey

    @apiKey.setter
    def apiKey(self, apiKey):
        self.__apiKey = apiKey

    @property
    def sslVerify(self):
        return self.__sslVerify

    @sslVerify.setter
    def sslVerify(self, sslVerify):
        self.__sslVerify = sslVerify

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, port):
        self.__port = port

    @property
    def tenant(self):
        return self.__tenant

    @tenant.setter
    def tenant(self, tenant):
        self.__tenant = tenant

    @property
    def Debug(self):
        return self.__Debug

    @Debug.setter
    def Debug(self, Debug):
        self.__Debug = Debug


