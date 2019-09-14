
import datetime
import logging
import os
import select
import signal
import yaml
from prometheus_client import start_http_server as prometheus_start_http_server, MetricsHandler
from socketserver import ThreadingMixIn
from http.server import HTTPServer
from urllib.parse import urlparse
from typing import List, Tuple

from .client import Client
from .types import ClientSettings

log = logging.getLogger('burp_exporter.daemon')


try:
    import systemd.daemon
    log.info('Systemd module detected')
    HAVE_SYSTEMD = True
except ImportError:
    log.info('Not using systemd module')
    HAVE_SYSTEMD = False


class ConfigError(Exception):
    pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class BurpHandler(MetricsHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == '/':
                self.send_html()
        except Exception as e:
            self.send_error(500, str(e))

    def send_html(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write('''<html><head><title>Burp Exporter</title></head><body><p>Hi!</p></body></html>''')


class Daemon:

    def __init__(self, cfg_file: str, timeout: int = 5):
        log.info('Starting up')

        self._clients = list()  # type: List[Client]

        cfg_path = os.path.expanduser(cfg_file)
        if not os.path.exists(cfg_path):
            msg = f'Config file {cfg_path} not found'
            log.critical(msg)
            raise Exception(msg)
        self._cfg_path = cfg_path

        try:
            self._bind_address, self._bind_port = self.read_config()
        except ConfigError as e:
            log.critical(f'Error during config parsing: {str(e)}')
            raise

        self._timeout = timeout

        # set to true to stop the main loop
        self._stop = False

        # sanity checks
        if self._bind_port <= 1024 or self._bind_port > 65535:
            log.error(f'bind_port is outside of range (1024, 65535), resetting to default')
            self._bind_port = 9645

        # start monitoring endpoint
        log.info(f'Binding monitoring to {self._bind_address}:{self._bind_port}')
        prometheus_start_http_server(addr=str(self._bind_address), port=self._bind_port)

        if HAVE_SYSTEMD:
            log.info('Signaling readiness')
            systemd.daemon.notify('READY=1')

        # set up signal handler
        signal.signal(signal.SIGTERM, self.signal_handler)

    @property
    def bind_address(self) -> str:
        return self._bind_address

    @property
    def bind_port(self) -> int:
        return self._bind_port

    def add_client(self, client: Client) -> None:
        for c in self._clients:
            if c.name == client.name:
                log.info(f'Replacing client {client.name}')
                del c

        self._clients.append(client)

    def run(self) -> None:
        '''
        Daemon main loop. The loop wait is done using the select call in read(). Loops until _stop is False.
        '''
        while not self._stop:
            log.debug('begin main loop')
            sockets = list()
            for client in self._clients:
                if not client.connected:
                    if client.last_connect_attempt < datetime.datetime.utcnow() - datetime.timedelta(minutes=1):
                        log.debug(f'Last connection attempt for {client} was {client.last_connect_attempt}')
                        if client.socket:
                            client.teardown_socket()
                        try:
                            client.setup_socket()
                        except ConnectionRefusedError:
                            log.warning(f'Connection refused for "{client}"')
                            client.teardown_socket()
                        else:
                            try:
                                client.connect()
                            except IOError as e:
                                log.critical(f'Error for {client} during handshake: {str(e)}')
                                client.teardown_socket()
                    else:
                        log.info(f'Client {client} has no connection')

                else:
                    sockets.append(client.socket)
                    client.refresh()

            log.debug('end main loop, sleeping')
            try:
                r, _, _ = select.select(sockets, [], [], self._timeout)
                log.debug(f'Checked for receive on {len(sockets)} clients')
                for client in self._clients:
                    if client.socket in r:
                        log.debug(f'Data available for {client}')
                        client.read()
            except KeyboardInterrupt:
                log.info('Got keyboard interrupt, shutting down')
                self._stop = True

        log.info('Shutting down')
        if HAVE_SYSTEMD:
            systemd.daemon.notify('STOPPING=1')
        # put cleanup code here
        for client in self._clients:
            client.teardown_socket()

    def signal_handler(self, signum, frame) -> None:
        '''
        Signal handler.

        * SIGTERM: set _stop to True, to halt the application
        * SIGHUB: read config file and update clients
        * others: ignored
        '''
        if signum == signal.SIGTERM:
            log.info('Caught SIGTERM, shutting down')
            self._stop = True
        if signum == signal.SIGHUP:
            log.info('Caught SIGHUP, reloading config')
            self.read_config()
        else:
            log.warning(f'Got signal {signum}, ignoring')

    def read_config(self) -> Tuple[str, int]:
        '''
        Reads the yaml config at the given `path`. It returns a tuple (bind_address, bind_port) and manages the list
        of clients, thus can be used to reload the configuration.
        '''
        cfg_path = os.path.expanduser(self._cfg_path)
        log.debug(f'Attempting to read config file "{cfg_path}"')
        if not os.path.exists(cfg_path):
            raise ConfigError(f'Configuration file not found at {cfg_path}')

        with open(cfg_path, 'rt') as fh:
            cfg = yaml.safe_load(fh.read())

        if 'bind_address' not in cfg:
            raise ConfigError('bind port not found')
        if 'bind_port' not in cfg:
            raise ConfigError('bind_port not found')

        if 'clients' not in cfg:
            log.warning('No clients in config')
        else:
            for c_conf in cfg['clients']:
                if 'name' not in c_conf:
                    raise ConfigError('client missing name')
                missing: List[str] = list()
                for var in ['burp_host', 'burp_port', 'burp_cname', 'cname', 'password', 'tls_ca_cert', 'tls_cert', 'tls_key']:
                    if var not in c_conf:
                        missing.append(var)
                if missing:
                    raise ConfigError(f'Client {c_conf["name"]} is missing mandatory settings: {missing}')

                # TODO error handling
                cl_cfg = ClientSettings(**c_conf)
                # self._clients.append(Client(cl_cfg))
                self.add_client(Client(cl_cfg))

        return cfg['bind_address'], cfg['bind_port']
