
import datetime
import json
import logging
import select
import signal
import socket
import ssl
import time
from prometheus_client import start_http_server as prometheus_start_http_server
from prometheus_client import Counter, Enum, Gauge
from pydantic import ValidationError
from typing import Optional, Set

from .settings import Settings
from .types import ClientInfo

log = logging.getLogger('burp_exporter.daemon')


try:
    import systemd.daemon
    log.info('Systemd module detected')
    HAVE_SYSTEMD = True
except ImportError:
    log.info('Not using systemd module')
    HAVE_SYSTEMD = False

#: Version of burp we're pretending to be
BURP_CLIENT_VERSION = '2.1.28'

# operational
SERVER_LAST_CONTACT = Gauge('burp_last_contact', 'Time when the burp server was last contacted')
SERVER_CONTACT_ATTEMPTS = Counter('burp_contact_attempts', 'Amount of times it was tried to establish a connection')
SERVER_UP = Gauge('burp_up', 'Shows if the connection to the server is up')
PARSE_ERRORS = Counter('burp_parse_errors', 'Amount of time parsing the server response failed')

# statistics
CLIENT_COUNT = Gauge('burp_clients', 'Number of clients known to the server')

# clients
CLIENT_BACKUP_NUM = Gauge('burp_client_backup_num', 'Number of the most recent backup for a client', ['name'])
CLIENT_BACKUP_TIMESTAMP = Gauge('burp_client_backup_timestamp', 'Timestamp of the most recent backup', ['name'])
CLIENT_BACKUP_LOGS = Gauge('burp_client_backup_log', 'Presence of logs for the most recent backup', ['name', 'log'])
CLIENT_BACKUP_HAS_IN_PROGRESS = Gauge('burp_client_backup_has_in_progress', 'Indicates whether a backup with flag "working" is present', ['name'])
CLIENT_RUN_STATUS = Enum('burp_client_run_status', 'Current run status of the client', ['name'], states=['running', 'idle'])


class Daemon:

    def __init__(self, settings: Settings):
        log.info('Starting up')

        self._settings = settings

        # set to true to stop the main loop
        self._stop = False
        # time when the values were updated last time
        self._ts_last_query = datetime.datetime.min
        #: If not connected, last time we tried to connect
        self._ts_last_connect_attempt = datetime.datetime.min
        # indicates if we have completed logging in to the burp server
        self._connected = False
        # remember the client names
        self._clients: Set[str] = set()

        # sanity checks
        if self._settings.bind_port <= 1024 or self._settings.bind_port > 65535:
            log.error(f'bind_port is outside of range (1024, 65535), resetting to default')
            self._settings.bind_port = 9645

        # start monitoring endpoint
        log.info(f'Binding monitoring to {self._settings.bind_address}:{self._settings.bind_port}')
        prometheus_start_http_server(addr=str(self._settings.bind_address), port=self._settings.bind_port)

        if HAVE_SYSTEMD:
            log.info('Signaling readiness')
            systemd.daemon.notify('READY=1')

        # set up signal handler
        signal.signal(signal.SIGTERM, self.signal_handler)

        # setup socket
        self._socket = None  # type: Optional[ssl.SSLSocket]

    @property
    def clients(self) -> Set[str]:
        return self._clients

    def setup_socket(self) -> None:
        '''
        Creates a communication socket and wraps it in an SSL context. This function handles the low-level connection,
        use :func:`~burp_exporter.daemon.Daemon.connect` to perform the handshake with the server.
        '''
        if not self._socket:
            log.debug(f'Creating socket: {self._settings.burp_host}:{self._settings.burp_port}')
            self._connected = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(True)
            sock.connect((self._settings.burp_host, self._settings.burp_port))

            log.debug(f'Creating SSL context. CA-cert: {self._settings.tls_ca_cert}, cert: {self._settings.tls_cert}, key: {self._settings.tls_key}')
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self._settings.tls_ca_cert)
            context.load_cert_chain(certfile=self._settings.tls_cert, keyfile=self._settings.tls_key)
            context.check_hostname = True

            log.debug('Wrapping socket')
            self._socket = context.wrap_socket(sock, server_side=False, server_hostname=self._settings.burp_cname)

            cert = self._socket.getpeercert()
            if not cert:
                raise Exception('No cert from peer')
            ssl.match_hostname(cert, self._settings.burp_cname)
            log.debug('Socket setup done')

    def teardown_socket(self) -> None:
        '''
        Closes the socket and frees it.
        '''
        self._connected = False
        if self._socket:
            # TODO flush buffers?
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
            del self._socket
            self._socket = None
            log.info('Socket teardown complete')

    def write_command(self, cmd: str, data: str) -> None:
        '''
        Writes the command `cmd` (single character) along with the `data` to the server.

        :param cmd: Single byte for the command, usually 'c'.
        :param data: Data to send as a payload.
        '''
        if not self._socket:  # no check for _connected, we're using this to set up the connection
            raise IOError('No socket')
        # TODO check if ascii
        if len(cmd) > 1:
            raise IOError('Command must be a single character')
        wstring = '%c%04X%s\0' % (cmd, len(data) + 1, data)
        log.debug(f'write_command: {wstring}')
        self._socket.write(wstring.encode('utf-8'))

    def read(self, bufsize: int = 2048) -> Optional[str]:
        '''
        Reads available data from the socket. Up to `bufsize` bytes are read at once, looping to get everything. If no
        data is returned, ``None`` is returned. If the socket is found to have closed, it will tear it down and return
        ``None`` as well. The timeout for waiting for data can be adjusted using :ref:`~burp_exporter.settings.Settings.timeout_seconds`.
        Data is converted to a string before returning, making this function unsuitable for handling binary data.

        :param bufsize: Amount of bytes that are read from the socket at once, though it loops to get all available data.
        :return: The data from the server or None if either nothing available or the socket being closed.
        '''
        if not self._socket:
            raise IOError('No socket')
        data = b''
        while 1:
            r, _, _ = select.select([self._socket], [], [], self._settings.timeout_seconds)
            if self._socket not in r:
                log.debug('read: timeout elapsed')
                break
            rec_data = self._socket.read(bufsize)
            reclen = len(rec_data)
            if reclen == 0:
                log.warning('Received no data, but socket indicated read readiness. Closing')
                self.teardown_socket()
                break
            log.debug(f'Read {reclen} bytes')
            data += rec_data
            if reclen < bufsize:
                break
        if len(data) == 0:
            log.debug('No data, timeout elapsed')
        return data.decode('utf-8')

    def run(self) -> None:
        '''
        Daemon main loop. The loop wait is done using the select call in read(). Loops until _stop is False.
        '''
        while not self._stop:
            log.debug('begin main loop')
            if not self._connected:
                SERVER_UP.set(0)
                if self._ts_last_connect_attempt < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                    log.debug(f'Last connection attempt was {self._ts_last_connect_attempt}')
                    self._ts_last_connect_attempt = datetime.datetime.utcnow()
                    if self._socket:
                        self.teardown_socket()
                    try:
                        self.setup_socket()
                    except ConnectionRefusedError:
                        log.warning('Got connection refused')
                        self.teardown_socket()
                    else:
                        try:
                            self.connect()
                        except IOError as e:
                            log.critical(f'Error during handshake: {str(e)}')
                            self.teardown_socket()
                else:
                    log.info('No connection, sleeping before retry')
                    try:
                        time.sleep(60)
                    except KeyboardInterrupt:
                        log.info('Keyboard interrupt in connect sleep, shutting down')
                        self._stop = True

            else:
                SERVER_UP.set(1)
                if self._ts_last_query < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                    log.debug(f'Last query was {self._ts_last_query}')
                    self._ts_last_query = datetime.datetime.utcnow()
                    self.write_command('c', 'c:')
                    SERVER_LAST_CONTACT.set_to_current_time()

                log.debug('end main loop, sleeping')
                try:
                    data = self.read()
                    if data:
                        self.handle_data(data)
                except KeyboardInterrupt:
                    log.info('Got keyboard interrupt, shutting down')
                    self._stop = True
                CLIENT_COUNT.set(len(self._clients))

        log.info('Shutting down')
        if HAVE_SYSTEMD:
            systemd.daemon.notify('STOPPING=1')
        self.teardown_socket()
        # put cleanup code here

    def signal_handler(self, signum, frame) -> None:
        '''
        Signal handler. For SIGTERM, _stop is set to True. All other signals are ignored.
        '''
        if signum == signal.SIGTERM:
            log.info('Caught SIGTERM, shutting down')
            self._stop = True
        else:
            log.warning(f'Got signal {signum}, ignoring')

    def handle_data(self, data: str) -> None:
        '''
        Takes data read from the socket and tries to make sense of it. If the payload can be parsed as json, it is
        handed over to :func:`~burp_exporter.daemon.Daemon.parse_message`, which takes it from there.
        One special case is the message ``c0001\n`` that is handed over from burp at the end of each message after
        json pretty printing has been turned off. If that value is found, it is discarded silently.
        '''
        if data[0] not in ['c', 'w']:
            raise IOError(f'Unexpected code {data[0]} in message {data}')
        # split into messages if we received multiple
        while True:
            mtype = data[0]
            dlen = len(data)
            # when using 'j:pretty-print-off', an empty message is sent. swallow it
            if dlen == 6 and data == 'c0001\n':
                break
            if dlen < 5:
                raise Exception('Message too short')
            try:
                mlen = int(data[1:5], 16)
            except ValueError as e:
                raise Exception('Invalid length in message') from e
            if not dlen == mlen + 5:
                raise Exception(f'Expected {mlen} payload length, but got {dlen - 5}')

            mdata = data[5:mlen + 5]
            if mtype == 'c':
                try:
                    json_data = json.loads(mdata)
                except json.JSONDecodeError as e:
                    log.warning('Could not decode data: ' + str(e))
                    raise
                self.parse_message(json_data)
            elif mtype == 'w':
                log.warning(f'Got warning: {mdata}')
            else:
                raise Exception(f'Unexpected message type {mtype}')

            data = data[mlen + 5:-1]
            if len(data) < 1:
                log.debug('end of data')
                break

    def parse_message(self, message: dict) -> None:
        '''
        Parses a json message received from the server. Right now, only the ``clients`` list is understood, everything
        else raises an exception.
        '''
        if 'clients' in message:
            clients: Set[str] = set()
            for client in message['clients']:
                try:
                    info = ClientInfo(**client)
                except ValidationError as e:
                    log.warning(f'Validation error: {str(e)}')
                    PARSE_ERRORS.inc()
                else:
                    # TODO validate name
                    clients.add(info.name)
                    if info.name not in self._clients:
                        log.debug(f'New client: {info.name}')
                        self._clients.add(info.name)
                    if info.backups:
                        has_working = False
                        for b in info.backups:
                            if 'current' in b.flags:
                                CLIENT_BACKUP_NUM.labels(name=info.name).set(b.number)
                                CLIENT_BACKUP_TIMESTAMP.labels(name=info.name).set(b.timestamp)
                            elif 'working' in b.flags:
                                # TODO figure out what to do
                                has_working = True
                                pass
                            # TODO logs
                        CLIENT_BACKUP_HAS_IN_PROGRESS.labels(name=info.name).set(1 if has_working else 0)
                    CLIENT_RUN_STATUS.labels(name=info.name).state(info.run_status)

            # compile a list of clients that are no longer included in the server response
            removed_clients = [x for x in self._clients if x not in clients]
            for name in removed_clients:
                try:
                    CLIENT_BACKUP_NUM.remove(name)
                    CLIENT_BACKUP_TIMESTAMP.remove(name)
                    CLIENT_BACKUP_LOGS.remove(name)
                    CLIENT_RUN_STATUS.remove(name)
                except KeyError:
                    pass
                self._clients.remove(name)
        else:
            log.warning(f'Unknown message: {message}')
            raise Exception('Unknown data')

    def connect(self) -> None:
        '''
        Performs the handshake with the burp server.
        '''
        if not self._socket:
            raise IOError('No socket')
        if self._connected:
            raise Exception('Already connected')

        self.write_command('c', f'hello:{BURP_CLIENT_VERSION}')
        data = self.read()
        if data and 'whoareyou' in data:
            if ':' in data:
                self._server_version = data.split(':')[-1]
        else:
            raise IOError('Did not receive whoareyou')

        self.write_command('c', self._settings.cname)
        data = self.read()
        if not data or 'okpassword' not in data:
            raise IOError(f'Unexpected data: {data}')

        # TODO handle no password case
        self.write_command('c', self._settings.password)

        data = self.read()
        if not data:
            raise IOError('No data after sending password')
        if data.startswith('w'):
            log.warning(f'Received warning from server: {data[5:]}')
            data = self.read()
        if not data or 'ok' not in data:
            raise IOError('No ok after sending password')

        self.write_command('c', 'nocsr')
        data = self.read()
        if not data or 'nocsr ok' not in data:
            raise IOError('Didn\'t receive "nocsr ok"')

        self.write_command('c', 'extra_comms_begin')
        data = self.read()
        if not data or 'extra_comms_begin ok' not in data:
            raise IOError('Error after requesting extra_comms')

        if ':counters_json:' in data:
            self.write_command('c', 'counters_json ok')
        if ':uname:' in data:
            self.write_command('c', 'uname=Linux')
        if ':msg:' in data:
            self.write_command('c', 'msg')

        self.write_command('c', 'extra_comms_end')
        data = self.read()
        if not data or 'extra_comms_end ok' not in data:
            raise IOError(f'Error signaling end of extra comms: {data}')

        # disable pretty printing
        self.write_command('c', 'j:pretty-print-off')
        self.read()
        # from now on, there will be a message '\n' after every message from the server. This only happens after json
        # pretty printing was turned on.
        self.read()
        self._connected = True
