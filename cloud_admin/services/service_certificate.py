from cloud_admin.services import EucaBaseObj

class ServiceCertificate(EucaBaseObj):
    """
    Used to parse and objectify the DescribeServiceCertificate response.
    """
    def __init__(self, connection=None):
        self.certificate = None
        self.certificatefingerprint = None
        self.certificatefingerprintdigest = None
        self.certificateformat = None
        self.certificateusage = None
        self.connection = None
        super(ServiceCertificate, self).__init__(connection)


    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'certificateusage':
                self.certificateusage = value
                if self.name is None:
                    self.name = value
            else:
                setattr(self, ename.lower(), value)

