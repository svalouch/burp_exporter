
import json
import pytest

from burp_exporter.parser import Parser


data_3c = '''{"clients":[{"name":"asdf","labels":["label1","label2"],"run_status":"idle","protocol":1,"backups":[]},{"name":"burp","labels":["team=cs","test"],"run_status":"idle","protocol":1,"backups":[{"number":4,"timestamp":1567146136,"flags":["current","manifest"],"logs":{"list":["backup","backup_stats"]}}]},{"name":"testclient","run_status":"idle","protocol":1,"backups":[]}]}'''
data_2c = '''{"clients":[{"name":"asdf","labels":["label1","label2"],"run_status":"idle","protocol":1,"backups":[]},{"name":"burp","labels":["team=cs","test"],"run_status":"idle","protocol":1,"backups":[{"number":4,"timestamp":1567146136,"flags":["current","manifest"],"logs":{"list":["backup","backup_stats"]}}]}]}'''


class TestParser:

    def test_init(self):
        p = Parser()
        assert len(p.clients) == 0

    def test_parser_3clients(self):
        p = Parser()
        p.parse_message(json.loads(data_3c))
        assert len(p.clients) == 3

    def test_parser_remove_client(self):
        '''
        A client has been removed (by removing its config in clientconfdir)
        '''
        p = Parser()
        p.parse_message(json.loads(data_3c))
        assert len(p.clients) == 3
        p.parse_message(json.loads(data_2c))
        assert len(p.clients) == 2
