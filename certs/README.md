Certificates
============

This folder contains a sample certificate and key that you can use in Janus for everything that's related to security, most importantly DTLS-SRTP and, in case you need it (see the deployment instructions in the docs on why you may not), for HTTPS and/or secure WebSockets as well. Please beware that these certificates are just for testing: they're self signed and not certificated by any authority (and certainly not by us!).

You can change the certificates to use in the ```janus.cfg``` settings. Should you want to generate some certificates yourself, refer to the instructions on how to do so that can be found pretty much everywhere.

Please beware, though, that 512 bit certificates should be avoided, as explained in #251.

# Feeling lazy?
Just as an example and for the lazy (you'll probably find better samples around), here's how you can quickly create a certificate as needed by Janus:

	openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

Just follow the instructions. This will create a private key in ```privateKey.key``` and a certificate in ```certificate.crt```. To use them, update the configuration file ```janus.cfg``` accordingly, to have the ```cert_pem``` and ```cert_key``` in ```[certificates]``` point to the newly created files.

If you are in need of certificates for use by browsers, for instance for the HTTP or WebSockets transports,
you can get them from many Certificate Authorities including Letsencrypt.org, a CA that signs certificates
for free and automatically using scripts on your server.
