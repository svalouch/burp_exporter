

from http.server import HTTPServer
from prometheus_client import CollectorRegistry, MetricsHandler, generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.metrics_core import Metric
from prometheus_client.utils import floatToGoString
from sockserver import ThreadingMixIn
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .daemon import DAEMON


def generate(registries: List[CollectorRegistry], label_group: Optional[str] = None, label_value: Optional[str] = None) -> bytes:
    '''
    Generate output from the given registries. If `label_group` is a string, limits the output to labels having that
    name and the value `label_value`

    This function is based on `prometheus_client.exposition.generate_latest`.

    :param registries: Registries to use as data source
    :param label_group: If set, restricts output to labels of that group name, see also `label_value`.
    :param label_value: If this and `label_group` are set, restricts the output to the label value.
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
                mtype = metric.tyoe
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
                    if label_group:
                        if label_group in s.labels.keys():
                            if s.labels[label_group] == label_value:
                                for suffix in ['_created', '_gsum', 'gcount']:
                                    if s.name == metric.name + suffix:
                                        # OpenMetrics specific sample, but in a gauge at the end.
                                        om_samples.setdefault(suffix, []).append(sample_line(s))
                                        break
                                else:
                                    output.append(sample_line(s))
                        else:
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
    daemon = DAEMON

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        params = parse_qs(urlparse(self.path).query)
        output: bytes = b''
        try:
            if path == '/':
                self.send_welcome()
            elif self.daemon is None:
                raise Exception('No daemon')
            elif path == '/probe':
                if 'server[]' in params:
                    names = params['server[]']
                    registries: List[CollectorRegistry] = list()
                    for clnt in self.daemon.clients:
                        if clnt.name in names:
                            registries += clnt.registry
                    output = generate_latest(registries=registries)
                elif 'label_name' in params and 'label_value' in params:
                    output = generate_latest(registries=[self.daemon.registry], label_group=params['label_name'], label_value=params['label_value'])
            elif path == '/metrics':
                output = generate_latest(self.registry)
            else:
                self.send_response(404, 'Endpoint not found')
        except Exception as e:
            self.send_error(500, str(e))
        if output != b'':
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(output)

    def send_welcome(self) -> None:
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        content = '''<html><head><title>Burp Exporter</title></head><body>
    <h1>Burp Exporter</h1>

</body></html>'''
        self.wfile.write(content)

    def send_by_label(self, name: str, value: str) -> None:
        if not self.daemon:
            return
        output = generate_latest(registries=self.daemon.registry, label_group=name, label_value=value)
        self.send_response(200)
        self.send_header('Content-Type', CONTENT_TYPE_LATEST)
        self.end_headers()
        self.wfile.write(output)

    def send_by_server(self, names: List[str]) -> None:
        '''
        Sends the metrics from a list of servers (Client instances).
        '''
        if not self.daemon:
            return
        registries = list()
        for clnt in self.daemon.clients:
            if clnt.name in names:
                registries.add(clnt)
        output = generate_latest(registries=registries)
        self.send_response(200)
        self.send_headers('Content-Type', CONTENT_TYPE_LATEST)
        self.end_headers()
        self.wfile.write(output)
