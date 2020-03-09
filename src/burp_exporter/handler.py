

import logging
import threading
from pkg_resources import get_distribution
from prometheus_client import CollectorRegistry, generate_latest, MetricsHandler, CONTENT_TYPE_LATEST
from prometheus_client.exposition import _ThreadingSimpleServer
from prometheus_client.metrics_core import Metric
from prometheus_client.utils import floatToGoString
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

DAEMON = None
log = logging.getLogger('burp_exporter.handler')


def generate(registries: List[CollectorRegistry]) -> bytes:
    '''
    Generate output from the given registries.

    This function is based on `prometheus_client.exposition.generate_latest`.

    :param registries: Registries to use as data source
    :return: The generated string.
    '''

    def sample_line(line) -> str:
        if line.labels:
            labelstr = '{{{0}}}'.format(','.join(
                ['{0}="{1}"'.format(
                    k, v.replace('\\', r'\\').replace('\n', r'\n').replace('"', r'\"'))
                    for k, v in sorted(line.labels.items())]))
        else:
            labelstr = ''
        timestamp = ''
        if line.timestamp is not None:
            # Convert to milliseconds.
            timestamp = ' {0:d}'.format(int(float(line.timestamp) * 1000))
        return '{0}{1} {2}{3}\n'.format(
            line.name, labelstr, floatToGoString(line.value), timestamp)

    output: List[str] = list()
    for registry in registries:
        for metric in registry.collect():
            try:
                mname = metric.name
                mtype = metric.type
                # Munging from OpenMetrics into Prometheus format
                if mtype == 'counter':
                    mname += '_total'
                elif mtype == 'info':
                    mname += '_info'
                    mtype = 'gauge'
                elif mtype == 'stateset':
                    mtype = 'gauge'
                elif mtype == 'gaugehistogram':
                    # A gauge histogram is really a gauge,
                    # but this captures the structure better.
                    mtype = 'histogram'
                elif mtype == 'unknown':
                    mtype = 'untyped'

                output.append('# HELP {0} {1}\n'.format(
                    mname, metric.documentation.replace('\\', r'\\').replace('\n', r'\n')))
                output.append(f'# TYPE {mname} {mtype}\n')

                om_samples = {}
                for s in metric.samples:
                    for suffix in ['_created', '_gsum', 'gcount']:
                        if s.name == metric.name + suffix:
                            # OpenMetrics specific sample, but in a gauge at the end.
                            om_samples.setdefault(suffix, []).append(sample_line(s))
                            break
                    else:
                        output.append(sample_line(s))
            except Exception as exception:
                exception.args = (exception.args or ('',)) + (metric,)
                raise

            for suffix, lines in sorted(om_samples.items()):
                output.append(f'# TYPE {metric.name}{suffix}\n')
                output.extend(lines)
    return ''.join(output).encode('utf-8')


class BurpHandler(MetricsHandler):

    def do_GET(self) -> None:
        log.debug(f'do_GET {self.path}')
        path = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)
        output: bytes = b''
        try:
            if path == '/':
                self.send_welcome()
            elif DAEMON is None:
                raise Exception('No daemon')
            elif path == '/probe':
                if 'server[]' in params:
                    names = params['server[]']
                    registries: List[CollectorRegistry] = list()
                    for clnt in DAEMON.clients:
                        if clnt.name in names:
                            registries.append(clnt.registry)
                    output = generate(registries=registries)
                else:
                    output = generate(registries=[DAEMON.registry])
            elif path == '/metrics':
                output = generate_latest(self.registry)
            else:
                self.send_error(404, 'Endpoint not found')
        except Exception as e:
            self.send_error(500, str(e))
        if output != b'':
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)

    def send_welcome(self) -> None:
        log.debug('send_welcome')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        content = f'''<html><head><title>Burp Exporter</title></head><body>
    <h1>Burp Exporter {get_distribution('burp_exporter').version}</h1>

    <ul>
        <li><a href="/metrics">/metrics</a> - state overview</a></li>
        <li><a href="/probe">/probe</a> - all information</li>
        <li>/probe?server[]=servername - limit by server</li>
    </ul>

</body></html>'''
        self.wfile.write(content.encode('utf-8'))

    def send_by_server(self, names: List[str]) -> None:
        '''
        Sends the metrics from a list of servers (Client instances).
        '''
        if not DAEMON:
            return
        registries = list()
        for clnt in DAEMON.clients:
            if clnt.name in names:
                registries.add(clnt)
        output = generate(registries=registries)
        self.send_response(200)
        self.send_headers('Content-Type', CONTENT_TYPE_LATEST)
        self.end_headers()
        self.wfile.write(output)


def start_http_server(port: int, addr: str = '') -> None:
    httpd = _ThreadingSimpleServer((addr, port), BurpHandler)
    t = threading.Thread(target=httpd.serve_forever)
    t.daemon = True
    t.start()
