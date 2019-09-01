burp_exporter
#############

A simple daemon that exposes `Burp` client status for `Prometheus <https://prometheus.io>`_ to consume.

Burp is a backup software written by Graham Keeling. Check out the `homepage <https://burp.grke.org>`_ and the `GitHub project <https://github,com/grke/burp>`_ for more information.

The exporter connects to the ``status_port`` as if it was a monitoring client (similar to what ``burp -a s`` does) and periodically (once per minute) requests the current client state from the server. This information is then made available on the network in Prometheus-compatible format. It does not implement the certificate generation process, use a regular burp client to do that.
 
Quickstart
**********

To try it out, create a virtual environment and install it into it. Use a regualar burp client to create key and certificate. By default, the filenames are:

* ``ca.pem`` for the CA certificate
* ``client.key`` containing the clients TLS key
* ``client.pem`` for the certificate signed by the burp server's CA.

.. code-block:: shell-session

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv) $ pip install pip install git+https://github.com/svalouch/burp_exporter
    (venv) $ burp_exporter

Then browse to `<http://127.0.0.1:9645>`_. If something doesn't work, raise the debug level using the ``-d`` switch.
