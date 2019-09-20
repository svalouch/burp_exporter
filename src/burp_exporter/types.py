
from pydantic import BaseModel
from typing import Dict, List, Optional


class BackupInfo(BaseModel):
    '''
    Representation of a single entry in the "backups" list of a client's response.
    '''
    #: Sequential number of this backup
    number: int
    #: UNIX timestamp when this backup was made
    timestamp: int
    #: List of flags associated with this backup
    flags: List[str]
    #: List of logs available for this backup. The dict has one element "list" in it.
    logs: Optional[Dict[str, List[str]]]


class ClientInfo(BaseModel):
    '''
    Representation of a client entry.
    '''
    #: Name of the client
    name: str
    #: Labels associated with the client
    labels: Optional[List[str]]
    #: Run status (e.g. 'idle')
    run_status: str
    #: Configured protocol (0, 1 or 2)
    protocol: int
    #: List of backups
    backups: List[BackupInfo]

    def __eq__(self, other) -> bool:
        if type(other) == ClientInfo:
            return self.name == other.name
        elif type(other) == str:
            return self.name == other
        return False


class ClientSettings(BaseModel):

    #: Name of the client
    name: str
    #: Client CNAME
    cname: str
    #: Client password
    password: str
    #: How long between refresh cycles
    refresh_interval_seconds: int = 60
    #: Version we pretend to be
    version: str = '2.1.18'

    #: Address of the burp server
    burp_host: str
    #: Status port of the burp server
    burp_port: int
    #: CNAME of the burp server
    burp_cname: str

    #: CA certificate file
    tls_ca_cert: str
    #: Client certificate file
    tls_cert: str
    #: Client key file
    tls_key: str
