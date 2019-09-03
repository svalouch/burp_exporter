burp_exporter
#############

A simple daemon that exposes `Burp` client status for `Prometheus <https://prometheus.io>`_ to consume.

Burp is a backup software written by Graham Keeling. Check out the `homepage <https://burp.grke.org>`_ and the `GitHub project <https://github,com/grke/burp>`_ for more information.

The exporter connects to the ``status_port`` as if it was a monitoring client (similar to what ``burp -a s`` does) and periodically (once per minute) requests the current client state from the server. This information is then made available on the network in Prometheus-compatible format. It does not implement the certificate generation process, use a regular burp client to do that.
 
Quickstart
**********

To try it out, create a virtual environment and install it into it. Use a regular burp client to create key and certificate. By default, the filenames are:

* ``ca.pem`` for the CA certificate
* ``client.key`` containing the clients TLS key
* ``client.pem`` for the certificate signed by the burp server's CA.

.. code-block:: shell-session

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv) $ pip install pip install git+https://github.com/svalouch/burp_exporter
    (venv) $ burp_exporter

Then browse to `<http://127.0.0.1:9645>`_. If something doesn't work, raise the debug level using the ``-d`` switch.

Example output
**************
Appart from the python metrics, these are exported right now:
::

    # HELP burp_last_contact Time when the burp server was last contacted
    # TYPE burp_last_contact gauge
    burp_last_contact 1.5674878997216787e+09
    # HELP burp_contact_attempts_total Amount of times it was tried to establish a connection
    # TYPE burp_contact_attempts_total counter
    burp_contact_attempts_total 0.0
    # HELP burp_up Shows if the connection to the server is up
    # TYPE burp_up gauge
    burp_up 1.0
    # HELP burp_parse_errors_total Amount of time parsing the server response failed
    # TYPE burp_parse_errors_total counter
    burp_parse_errors_total 0.0
    # HELP burp_clients Number of clients known to the server
    # TYPE burp_clients gauge
    burp_clients 3.0
    # HELP burp_client_backup_num Number of the most recent backup for a client
    # TYPE burp_client_backup_num gauge
    burp_client_backup_num{name="burp"} 4.0
    # HELP burp_client_backup_timestamp Timestamp of the most recent backup
    # TYPE burp_client_backup_timestamp gauge
    burp_client_backup_timestamp{name="burp"} 1.567146136e+09
    # HELP burp_client_backup_log Presence of logs for the most recent backup
    # TYPE burp_client_backup_log gauge
    # HELP burp_client_backup_has_in_progress Indicates whether a backup with flag "working" is present
    # TYPE burp_client_backup_has_in_progress gauge
    burp_client_backup_has_in_progress{name="burp"} 0.0
    # HELP burp_client_run_status Current run status of the client
    # TYPE burp_client_run_status gauge
    burp_client_run_status{burp_client_run_status="running",name="asdf"} 0.0
    burp_client_run_status{burp_client_run_status="idle",name="asdf"} 1.0
    burp_client_run_status{burp_client_run_status="running",name="burp"} 0.0
    burp_client_run_status{burp_client_run_status="idle",name="burp"} 1.0
    burp_client_run_status{burp_client_run_status="running",name="testclient"} 0.0
    burp_client_run_status{burp_client_run_status="idle",name="testclient"} 1.0

There are three idle clients (`asdf`, `burp` and `testclient`), of which only `burp` has backups (last complete one is number 4). `burp` also has a backup in state "working", most likely due to being interrupted during backup. Also, ``burp_up`` shows that the connection to the server is established.
