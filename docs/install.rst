
############
Installation
############

At the time of writing, the recommended way to install the exporter is by using a virtual environment and using pip to get the desired version from the repository directly.

Requirements
************
The exporter requires `Python` version 3.6 (as present on Debian Buster (stable), Ubuntu 18.04 LTS, Gentoo Linux and other distributions). It is developed and tested on x86_64 Linux only, though it might work on other platforms and operating systems.

There is a small set of libraries required, most prominently:

* `prometheus_client <https://github.com/prometheus/client_python>`_ for exposing the metrics.
* `pydantic <https://pydantic-docs.helpmanual.io>`_ for working with the server response and the configuration

Sadly, there are very few distributions that natively package `prometheus_client` or `pydantic`.

Deployment options
******************

Configuration
=============
Regardless of actual deployment path, there are two ways to configure the code, and they can be mixed freely:

* via environment variables
* via command line options

Virtualenv setup (development)
==============================
For development, the following commands pull the source and prepare a virtual environment into which the software is installed `editable`, meaning that it behaves as if it was a normal python package, but the code can be edited freely:

.. code-block:: shell-session

    $ git clone https://host/burp_exporter.git
    $ cd burp_exporter
    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv) $ pip install -e .
    (venv) $ pip install -r requirements_develop.txt

This should have you set up. The command ``burp_exporter`` is installed into the virtualenvs ``$PATH``.

Deploying on a server
=====================
Similar to the deployment setup, the code can either be checked out and installed via pip, or downloaded and installed via pip. The command ``burp_exporter`` will become available in the designated bin directory.

Burp server
***********
For the exporter to be accepted by the burp server, it needs a certificate signed by the servers certificate authority, like a regular burp client would. By far the easiest way is to set up a normal burp client with the desired cname and connect to the burp server to have the certificate signed. Then transfer the key, certificate and ca certificate to the desired location for the exporter.

Take a look at the :ref:`settings` to get an idea how it comes together.
