
.. _settings:

########
Settings
########

Settings can be provided on the command line (see :ref:`cli`) or via environment variables. The CLI uses lower-case and dash (`-`), the environment method uses all upper-case, underscores and the prefix ``BURP_EXPORTER_``, but the actual name is the same for both of them. Here is a list of the environment variables:

.. option:: BURP_EXPORTER_BURP_HOST

    Address of the burp server.

.. option:: BURP_EXPORTER_BURP_PORT

    ``status_port`` on the burp server.

.. option:: BURP_EXPORTER_BURP_CNAME

    Common Name of the burp server, defaults to ``burpserver``.

.. option:: BURP_EXPORTER_CNAME

    Common Name of the client, must match the certificate.

.. option:: BURP_EXPORTER_PASSWORD

    Password used for connecting. Defaults to ``abcdefgh``.

.. option:: BURP_EXPORTER_TLS_CA_CERT

    Path to the CA certificate of the burp server. Defaults to ``ca.pem``.

.. option:: BURP_EXPORTER_TLS_CERT

    Path to the client TLS certificate, defaults to ``client.pem``.

.. option:: BURP_EXPORTER_TLS_KEY

    Path to a file containing the client TLS key, defaults to ``client.key``.

.. option:: BURP_EXPORTER_BIND_ADDRESS

    IP address to bind the metrics page to. Defaults to ``127.0.0.1``.

.. option:: BURP_EXPORTER_BIND_PORT

    Port to bind the metrics page to, defaults to ``9645``. See `BURP_EXPORTER_BIND_ADDRESS`.
