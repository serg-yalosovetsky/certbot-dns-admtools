certbot-dns-admtools
=====================

adm.tools DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the adm.tools Remote API.

Configuration of adm.tools
---------------------------

In the `System -> Remote Users` you have to have a user, with the following rights

- Client Functions
- DNS zone functions
- DNS txt functions


.. _adm.tools: https://adm.tools/
.. _certbot: https://certbot.eff.org/

Installation
------------

::

    pip install certbot-dns-admtools


Named Arguments
---------------

To start using DNS authentication for adm.tools, pass the following arguments on
certbot's command line:

============================================================= ==============================================
``--authenticator certbot-dns-admtools:dns-admtools``          select the authenticator plugin (Required)

``--certbot-dns-admtools:dns-admtools-credentials``         adm.tools Remote User credentials
                                                              INI file. (Required)

``--certbot-dns-admtools:dns-admtools-propagation-seconds`` | waiting time for DNS to propagate before asking
                                                              | the ACME server to verify the DNS record.
                                                              | (Default: 120, Recommended: >= 600)
============================================================= ==============================================

(Note that the verbose and seemingly redundant ``certbot-dns-admtools:`` prefix
is currently imposed by certbot for external plugins.)


Credentials
-----------

An example ``adm_tools.ini`` file:

.. code-block:: ini

   auth_token = myremoteuser_auth_token

The path to this file can be provided interactively or using the
``--certbot-dns-admtools:dns-admtools-credentials`` command-line argument. Certbot
records the path to this file for use during renewal, but does not store the
file's contents.

**CAUTION:** You should protect these API credentials as you would the
password to your adm.tools account. Users who can read this file can use these
credentials to issue arbitrary API calls on your behalf. Users who can cause
Certbot to run using these credentials can complete a ``dns-01`` challenge to
acquire new certificates or revoke existing certificates for associated
domains, even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

To acquire a single certificate for both ``example.com`` and
``*.example.com``, waiting 30 seconds for DNS propagation:

.. code-block:: bash

   certbot certonly \
     --authenticator dns-admtools \
     --preferred-challenges dns \
     --dns-admtools-credentials adm_tools.ini \
     --dns-admtools-propagation-seconds 30 \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     --email "email@example.com" \
     -d '*.example.com'


Docker
------

In order to create a docker container with a certbot-dns-admtools installation,
create an empty directory with the following ``Dockerfile``:

.. code-block:: docker

    FROM certbot/certbot
    RUN pip install certbot-dns-admtools

Proceed to build the image::

    docker build -t certbot/dns-admtools .

Once that's finished, the application can be run as follows::

    docker run --rm \
       -v /var/lib/letsencrypt:/var/lib/letsencrypt \
       -v /etc/letsencrypt:/etc/letsencrypt \
       --cap-drop=all \
       certbot/dns-admtools certonly \
       --authenticator certbot-dns-admtools:dns-admtools \
       --certbot-dns-admtools:dns-admtools-propagation-seconds 900 \
       --certbot-dns-admtools:dns-admtools-credentials \
           /etc/letsencrypt/.secrets/domain.tld.ini \
       --no-self-upgrade \
       --keep-until-expiring --non-interactive --expand \
       --server https://acme-v02.api.letsencrypt.org/directory \
       -d example.com -d '*.example.com'

It is suggested to secure the folder as follows::
chown root:root /etc/letsencrypt/.secrets
chmod 600 /etc/letsencrypt/.secrets
