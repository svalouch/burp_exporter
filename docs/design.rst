
######
Design
######

The exporter is a simple python daemon that runs continuously and connects to one burp server on the monitor port.

Other than programs like `Burp-UI <https://git.ziirish.me/ziirish/burp-ui>`_ (which you should definitely check out), the exporter implements the neccessary functionality to talk to the burp server itself, meaning that it does not need a burp binary run in monitor mode. It implements just enough to be able to fulfill its purpose. This means that it is not a supported "burp client" and might break randomly when something is changed in the burp server.

TLS handling
============
The program itself does not implement functionality to create a TLS key and have a certificate signed by the server. This part has to be done by the admin. It needs a TLS key, a certificate signed by the burp servers `certificate authority <https://burp.grke.org/docs/burp_ca.html>`_, the ca certificate and optionally a password, just like the regular burp client does.

Init-System
===========
If the `systemd` library is detected, the exporter reports its state to systemd as a `Notify` service. Systemd knows when the program has finished setting up or is about to shut down and can take action if desired.

The daemon works with other init systems, such das OpenRC, too: it simply skips the systemd-related code if the library could not be imported.
