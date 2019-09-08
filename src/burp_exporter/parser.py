
import logging
from pydantic import ValidationError
from typing import Set

from .metrics import CLIENT_BACKUP_NUM, CLIENT_BACKUP_TIMESTAMP, CLIENT_COUNT, CLIENT_RUN_STATUS
from .metrics import CLIENT_BACKUP_LOGS, CLIENT_BACKUP_HAS_IN_PROGRESS, PARSE_ERRORS
from .types import ClientInfo

log = logging.getLogger('burp_exporter.parser')


class Parser:

    def __init__(self) -> None:
        self._clients = set()  # type: Set[str]

    @property
    def clients(self) -> Set[str]:
        return self._clients

    def commit(self) -> None:
        '''commits the temporary list and cleans up'''
        CLIENT_COUNT.set(len(self.clients))
        pass

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
