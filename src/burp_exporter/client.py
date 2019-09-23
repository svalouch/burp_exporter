
import datetime
import json
import logging
import select
import socket as sock
import ssl

from prometheus_client.core import CollectorRegistry, CounterMetricFamily, GaugeMetricFamily
from pydantic import ValidationError
from typing import List, Optional, Set

from .types import ClientSettings, ClientInfo

#: Default value if group_by_label is not None and the client does not have the label
LABEL_DEFAULT = '--unknown--'


class Client:

    def __init__(self, config: ClientSettings, group_by_label: Optional[str] = None) -> None:
        self._config = config
        self._group_by_label = group_by_label
        self._log = logging.getLogger(f'burp_exporter.client.{self._config.name}')
        self._socket: Optional[ssl.SSLSocket] = None
        self._buf: bytes = b''
        self._connected: bool = False
        self._clients: List[ClientInfo] = list()
        self._ts_last_query: datetime.datetime = datetime.datetime.utcnow() - datetime.timedelta(seconds=self._config.refresh_interval_seconds)
        self._ts_last_connect_attempt: datetime.datetime = datetime.datetime.utcnow() - datetime.timedelta(seconds=self._config.refresh_interval_seconds)
        self._parse_errors: int = 0
        # indicates if a query waits for answer
        self._in_flight = False
        self._registry = CollectorRegistry()

        self._registry.register(self)

    def __repr__(self) -> str:
        return f'<Client("{self._config.name}")>'

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def socket(self) -> Optional[ssl.SSLSocket]:
        return self._socket

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def last_connect_attempt(self) -> datetime.datetime:
        return self._ts_last_connect_attempt

    @property
    def last_query(self) -> datetime.datetime:
        return self._ts_last_query

    @property
    def refresh_interval(self) -> int:
        return self._config.refresh_interval_seconds

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def registry(self) -> CollectorRegistry:
        return self._registry

    def refresh(self) -> None:
        '''
        Triggers a refresh by sending a command ("c:") to the server if the refresh interval has passed.
        '''
        if self._connected and self._ts_last_query < datetime.datetime.utcnow() - datetime.timedelta(seconds=self._config.refresh_interval_seconds):
            if self._in_flight:
                self._log.warning('Waiting for a query to return')
            else:
                self._ts_last_query = datetime.datetime.utcnow()
                self.write_command('c', 'c:')

    def collect(self):
        '''
        Custom collector endpoint.
        '''
        self._log.debug(f'collect() with {len(self._clients)} clients')
        burp_last_contact = GaugeMetricFamily('burp_last_contact', 'Time when the burp server was last contacted', labels=['server'])
        burp_last_contact.add_metric([self.name], self._ts_last_query.replace(tzinfo=datetime.timezone.utc).timestamp())
        yield burp_last_contact

        burp_up = GaugeMetricFamily('burp_up', 'Shows if the connection to the server is up', labels=['server'])
        burp_up.add_metric([self.name], 1 if self._connected else 0)
        yield burp_up

        burp_parse_errors = CounterMetricFamily('burp_parse_errors', 'Amount of time parsing the server response failed', labels=['server'])
        burp_parse_errors.add_metric([self.name], self._parse_errors)
        yield burp_parse_errors

        burp_clients = GaugeMetricFamily('burp_clients', 'Number of clients known to the server', labels=['server'])
        burp_clients.add_metric([self.name], len(self._clients))
        yield burp_clients

        group_label = [self._group_by_label] if self._group_by_label is not None else []
        cl_backup_num = GaugeMetricFamily('burp_client_backup_num', 'Number of the most recent completed backup for a client', labels=['server', 'name'] + group_label)
        cl_backup_ts = GaugeMetricFamily('burp_client_backup_timestamp', 'Timestamp of the most recent backup', labels=['server', 'name'] + group_label)
        cl_backup_has_in_progress = GaugeMetricFamily('burp_client_backup_has_in_progress', 'Indicates whether a backup with flag "working" is present', labels=['server', 'name'] + group_label)
        cl_run_status = GaugeMetricFamily('burp_client_run_status', 'Current run status of the client', labels=['server', 'name', 'run_status'] + group_label)

        for clnt in self._clients:
            has_working = False

            # handle grouping by label
            lval = []
            if self._group_by_label:
                for l in clnt.labels:
                    if l.startswith(f'{self._group_by_label}='):
                        lval = [l.split('=', 1)[1]]
                        break
                if not lval:
                    lval = [LABEL_DEFAULT]
                self._log.debug(f'Label: {self._group_by_label} = "{lval[0]}"')

            for b in clnt.backups:
                if 'current' in b.flags:
                    cl_backup_num.add_metric([self.name, clnt.name] + lval, b.number)
                    cl_backup_ts.add_metric([self.name, clnt.name] + lval, b.timestamp)
                elif 'working' in b.flags:
                    # TODO figure out what to do
                    has_working = True
                # TODO logs
            cl_backup_has_in_progress.add_metric([self.name, clnt.name] + lval, 1 if has_working else 0)
            cl_run_status.add_metric([self.name, clnt.name, 'running'] + lval, clnt.run_status == 'running')
            cl_run_status.add_metric([self.name, clnt.name, 'idle'] + lval, clnt.run_status == 'idle')

        yield cl_backup_num
        yield cl_backup_ts
        yield cl_backup_has_in_progress
        yield cl_run_status

    def setup_socket(self) -> None:
        '''
        Creates a communication socket and wrapps it in an SSL context. This function handles the low-level
        connection, use :func:`~burp_exporter.client.Client.connect` to perform the handshake with the server.
        '''
        if not self._socket:
            self._ts_last_connect_attempt = datetime.datetime.utcnow()
            self._log.debug(f'Creating socket: {self._config.burp_host}:{self._config.burp_port}')
            self._connected = False
            sck = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            sck.setblocking(True)
            try:
                sck.connect((self._config.burp_host, self._config.burp_port))
            except ConnectionRefusedError:
                self._log.warning('Connection refused')
                raise

            self._log.debug(f'Creating SSL context. CA-cert: {self._config.tls_ca_cert}, cert: {self._config.tls_cert}, key: {self._config.tls_key}')
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self._config.tls_ca_cert)
            context.load_cert_chain(certfile=self._config.tls_cert, keyfile=self._config.tls_key)
            context.check_hostname = True

            self._log.debug('Wrapping socket')
            self._socket = context.wrap_socket(sck, server_side=False, server_hostname=self._config.burp_cname)

            cert = self._socket.getpeercert()
            if not cert:
                raise Exception('No cert from peer')
            ssl.match_hostname(cert, self._config.burp_cname)
            self._log.debug('Socket setup done')

    def teardown_socket(self) -> None:
        '''
        Closes the socket and frees it.
        '''
        self._connected = False
        self._in_flight = False
        self._buf = b''
        if self._socket:
            # TODO flush buffers?
            self._socket.shutdown(sock.SHUT_RDWR)
            self._socket.close()
            del self._socket
            self._socket = None
            self._log.info('Socket teardown complete')

    def write_command(self, cmd: str, data: str) -> None:
        '''
        Writes the command `cmd` (single character) along with the `data` to the server.

        :param cmd: Single byte for the command, usually 'c'.
        :param data: Data to be send as payload.
        '''
        if not self._socket:  # no check for _connected, we're using this to set up the connection, too
            raise IOError('No socket')
        # TODO check if ascii
        if len(cmd) > 1:
            raise IOError('Command must be a single character')
        wstring = '%c%04X%s\0' % (cmd, len(data) + 1, data)
        self._socket.write(wstring.encode('utf-8'))

    def read(self, bufsize: int = 2048) -> None:
        '''
        Reads data from the socket. The function assumes that data is available and will block if not, so make sure to
        use `select`. Up to `bufsize` bytes are read. If more data is available, call it again until everything is
        received. If the end of the data is detected, calls the parser on it.

        :param bufsize: Amount of bytes that are read from the socket at once.
        '''
        if not self._socket:
            raise IOError('No socket')
        rec_data = self._socket.read(bufsize)
        reclen = len(rec_data)
        if reclen == 0:
            self._log.warning('Received no data, assuming loss of connection.')
            self.teardown_socket()
        else:
            self._log.debug(f'Read {reclen} bytes')
            self._buf += rec_data
            if reclen < bufsize:
                self.handle_data()
                self._in_flight = False

    def raw_read(self, bufsize: int = 2048) -> Optional[str]:
        '''
        Raw read function designed to be used when connecting (during handshake) only.
        '''
        if not self._socket:
            raise IOError('No socket')
        data = b''
        while 1:
            r, _, _ = select.select([self._socket], [], [], 10)
            if self._socket not in r:
                self._log.debug('raw_read: timeout elapsed')
                break
            rec_data = self._socket.read(bufsize)
            reclen = len(rec_data)
            if reclen == 0:
                self._log.warning('Received no data, but socket indicated read readiness. Closing')
                self.teardown_socket()
                break
            self._log.debug(f'Read {reclen} bytes')
            data += rec_data
            if reclen < bufsize:
                break
        if len(data) == 0:
            self._log.debug('No data, timeout elapsed')
        return data.decode('utf-8')

    def connect(self) -> None:
        '''
        Performs the handshake with the burp server.
        '''
        if not self._socket:
            raise IOError('No socket')
        if self._connected:
            raise Exception('Already connected')

        self.write_command('c', f'hello:{self._config.version}')
        data = self.raw_read()
        if data and 'whoareyou' in data:
            if ':' in data:
                self._server_version = data.split(':')[-1]
        else:
            raise IOError('Did not receive whoareyou')

        self.write_command('c', self._config.cname)
        data = self.raw_read()
        if not data or 'okpassword' not in data:
            raise IOError(f'Unexpected data: {data}')

        # TODO handle no password case
        self.write_command('c', self._config.password)

        data = self.raw_read()
        if not data:
            raise IOError('No data after sending password')
        if data.startswith('w'):
            self._log.warning(f'Received warning from server: {data[5:]}')
            data = self.raw_read()
        if not data or 'ok' not in data:
            raise IOError('No ok after sending password')

        self.write_command('c', 'nocsr')
        data = self.raw_read()
        if not data or 'nocsr ok' not in data:
            raise IOError('Didn\'t receive "nocsr ok"')

        self.write_command('c', 'extra_comms_begin')
        data = self.raw_read()
        if not data or 'extra_comms_begin ok' not in data:
            raise IOError('Error after requesting extra_comms')

        if ':counters_json:' in data:
            self.write_command('c', 'counters_json ok')
        if ':uname:' in data:
            self.write_command('c', 'uname=Linux')
        if ':msg:' in data:
            self.write_command('c', 'msg')

        self.write_command('c', 'extra_comms_end')
        data = self.raw_read()
        if not data or 'extra_comms_end ok' not in data:
            raise IOError(f'Error signaling end of extra comms: {data}')

        # disable pretty printing
        self.write_command('c', 'j:pretty-print-off')
        self.raw_read()
        # from now on, there will be a message '\n' after every message from the server. This only happens after json
        # pretty printing was turned on.
        self.raw_read()
        self._connected = True

    def handle_data(self) -> None:
        '''
        Takes data read from the socket and tries to make sense of it. If the payload can be parsed as json, it is
        handed over to :func:`~burp_exporter.daemon.Daemon.parse_message`, which takes it from there.
        One special case is the message ``c0001\n`` that is handed over from burp at the end of each message after
        json pretty printing has been turned off. If that value is found, it is discarded silently.
        '''
        buf = self._buf.decode('utf8')
        if buf[0] not in ['c', 'w']:
            raise IOError(f'Unexpected code {buf[0]} in message {buf}')
        # split into messages if we received multiple
        while True:
            mtype = buf[0]
            dlen = len(buf)
            # when using 'j:pretty-print-off', an empty message is sent. swallow it
            if dlen == 6 and buf == 'c0001\n':
                break
            if dlen < 5:
                raise Exception('Message too short')
            try:
                mlen = int(buf[1:5], 16)
            except ValueError as e:
                raise Exception('Invalid length in message') from e
            if not dlen == mlen + 5:
                raise Exception(f'Expected {mlen} payload length, but got {dlen - 5}')

            mdata = buf[5:mlen + 5]
            if mtype == 'c':
                try:
                    json_data = json.loads(mdata)
                except json.JSONDecodeError as e:
                    self._log.warning('Could not decode data: ' + str(e))
                    raise
                self.parse_message(json_data)
            elif mtype == 'w':
                self._log.warning(f'Got warning: {mdata}')
            else:
                raise Exception(f'Unexpected message type {mtype}')

            data = buf[mlen + 5:-1]
            if len(data) < 1:
                self._log.debug('end of data')
                break
        self._buf = b''

    def parse_message(self, message: dict) -> None:
        '''
        Parses a json message received from the server. Right now, only the ``clients`` list is understood, everything
        else raises an exception.
        '''
        self._log.debug(f'parse_message: {message}')
        if 'clients' in message:
            clients: Set[str] = set()
            for client in message['clients']:
                try:
                    info = ClientInfo(**client)
                except ValidationError as e:
                    self._log.warning(f'Validation error: {str(e)}')
                    self._parse_errors += 1
                else:
                    # TODO validate name
                    clients.add(info.name)
                    if info.name not in self._clients:
                        self._log.debug(f'New client: {info.name}')
                        self._clients.append(info)
                    else:
                        self._log.debug(f'Updating client: {info.name}')
                        # TODO meditate over performance
                        self._clients = [info if cl.name == info.name else cl for cl in self._clients]

            self._log.debug(f'List before cleanup: {self._clients} | {clients}')
            # compile a list of clients that are no longer included in the server response
            self._clients = [x for x in self._clients if x.name in clients]
            self._log.debug(f'List after cleanup: {self._clients}')

        else:
            self._log.warning(f'Unknown message: {message}')
            raise Exception('Unknown data')
