
from pydantic import BaseSettings, IPvAnyAddress


class Settings(BaseSettings):

    # ### BURP ### #

    #: Address of the burp server
    burp_host: str = '127.0.0.1'
    #: Monitor port
    burp_port: int = 4972
    #: CNAME of the burp server
    burp_cname: str = 'burpserver'
    #: Timeout in seconds for burp communication
    timeout_seconds: int = 10

    #: Our own cname
    cname: str = 'burp'
    #: Our own pssword
    password: str = 'abcdefgh'

    # ### TLS ### #

    #: File containing the ca certificate
    tls_ca_cert: str = 'ca.pem'
    #: File containing the tls client certificate
    tls_cert: str = 'client.pem'
    #: File containing the tls client key
    tls_key: str = 'client.key'

    # ### Monitoring ### #

    #: IP to bind to
    bind_address: IPvAnyAddress = '127.0.0.1'
    #: Port to bind to
    bind_port: int = 9645

    class Config:
        env_prefix = 'BURP_EXPORTER_'
