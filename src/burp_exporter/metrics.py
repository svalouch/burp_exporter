
from prometheus_client import Counter, Enum, Gauge


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
