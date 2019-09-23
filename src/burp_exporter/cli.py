
import argparse
import logging
import sys
from pkg_resources import get_distribution

from . import handler
from .daemon import Daemon

__version__ = get_distribution('burp_exporter').version


def setup_argparse():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='''Daemon for exposing burp client status to a Prometheus server.

The exporter connects to one or more burp servers. It behaves like a regular
client and periodically queries each server to receive the client list.  The
client's status is then exposed in Prometheus exporter format.

The exporter does not create its own certificates, but used the ones generated
by a regular burp(8) client.''')
    parser.add_argument('-c', '--config', default='/etc/burp_exporter/burp_exporter.yaml', type=str, help='YAML configuration file, defaults to /etc/burp_exporter/burp_exporter.yaml')
    parser.add_argument('-d', '--debug', action='store_true', help='Log at debug level, print to stdout')
    parser.add_argument('--version', action='version', version=__version__)

    return parser


def cli():
    args = setup_argparse().parse_args()
    log = setup_logging(args.debug)

    try:
        handler.DAEMON = Daemon(args.config)
    except Exception as e:
        log.critical(f'Error during setup: {str(e)}')
        print(str(e))
        sys.exit(1)
    else:
        handler.DAEMON.run()


def setup_logging(debug: bool = False) -> logging.Logger:
    log = logging.getLogger('burp_exporter')
    if debug:
        log.setLevel(logging.DEBUG)
        debug_handler = logging.StreamHandler(sys.stdout)
        debug_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        debug_handler.setFormatter(formatter)
        log.addHandler(debug_handler)
    else:
        log.setLevel(logging.INFO)
    return log
