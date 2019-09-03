
import argparse
import logging
import sys
from pydantic import ValidationError

from .daemon import Daemon
from .settings import Settings


def setup_argparse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='''Daemon for exposing burp client status to a Prometheus server.

The exporter connects to a burp server like a regular client and periodically
queries it to receive the client list.  The client's status is then exposed
via Prometheus exporter format.

The exporter does not create its own certificates, but used the ones generated
by a regular burp(8) client.''')
    parser.add_argument('-H', '--burp-host', type=str, help='Address of the burp server')
    parser.add_argument('-P', '--burp-port', type=int, help='Monitor port on the burp server')
    parser.add_argument('-N', '--burp-cname', type=str, help='Server cname')

    parser.add_argument('-C', '--cname', type=str, help='Client cname, must match client certificate')
    parser.add_argument('-p', '--password', type=str, help='Password to authenticate with the server')

    parser.add_argument('-a', '--tls-ca-cert', type=str, help='File that contains the CA certificate')
    parser.add_argument('-k', '--tls-key', type=str, help='File that contains the key for the client certificate')
    parser.add_argument('-c', '--tls-cert', type=str, help='File that contains the client certificate')

    parser.add_argument('-m', '--bind-address', type=str, help='IP-address to bind the monitoring endpoint to')
    parser.add_argument('-M', '--bind-port', type=int, help='Port to bind the monitoring endpoint to')

    parser.add_argument('-d' '--debug', action='store_true', help='Log at debug level, print to stdout')

    return parser


def cli():
    args = setup_argparse().parse_args()
    log = setup_logging(args.d__debug)

    ovr = dict()
    if args.burp_host:
        ovr['burp_host'] = args.burp_host
    if args.burp_port:
        ovr['burp_port'] = args.burp_port
    if args.burp_cname:
        ovr['burp_cname'] = args.burp_cname

    if args.cname:
        ovr['cname'] = args.cname
    if args.password:
        ovr['password'] = args.password

    if args.tls_ca_cert:
        ovr['tls_ca_cert'] = args.tls_ca_cert
    if args.tls_key:
        ovr['tls_key'] = args.tls_key
    if args.tls_cert:
        ovr['tls_cert'] = args.tls_cert

    if args.bind_address:
        ovr['bind_address'] = args.bind_address
    if args.bind_port:
        ovr['bind_port'] = args.bind_port

    try:
        s = Settings(**ovr)
    except ValidationError as e:
        print_validation_error(e)
        sys.exit(1)

    d = Daemon(s)
    # we set this up here to speed up initialization
    try:
        d.setup_socket()
        d.connect()
    except ConnectionRefusedError as e:
        log.warning(f'Got connection refused: {e}')
    except IOError as e:
        log.critical(f'IO Error: {e}')

    d.run()


def setup_logging(debug: bool = False) -> logging.Logger:
    log = logging.getLogger('burp_exporter')
    if debug:
        log.setLevel(logging.DEBUG)
        debug_handler = logging.StreamHandler(sys.stdout)
        debug_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        debug_handler.setFormatter(formatter)
    else:
        log.setLevel(logging.INFO)
    return log


def print_validation_error(err: ValidationError) -> None:
    print(err)
