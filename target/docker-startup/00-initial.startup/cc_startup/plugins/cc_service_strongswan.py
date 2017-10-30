"""
This module contains everything needed to configure 'strongswan'.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
import re

from OpenSSL import crypto, SSL
from socket import gethostname
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from ..cc_helpers import read_text_file, write_text_file, replace_php_define, replace_php_variable, generate_password, get_env_setting_bool, get_env_setting_integer, get_env_setting_string
from ..cc_log import Log
from ..cc_service import Service

# ---------------------------------------------------------------------------------------------------------------------

# keys/certificates for evaulation/testing purposes (automatically generated, not for use in production environments)
INTERNAL_PKI_CA_CERT_FILE     = "/etc/ipsec.d/certs/internal/ca-cert.pem"
INTERNAL_PKI_CA_KEY_FILE      = "/etc/ipsec.d/private/internal/ca-key.pem"
INTERNAL_PKI_SERVER_CERT_FILE = "/etc/ipsec.d/certs/internal/vpn-server-cert.pem"
INTERNAL_PKI_SERVER_KEY_FILE  = "/etc/ipsec.d/private/internal/vpn-server-key.pem"

# keys/certificates for use in production environments
EXTERNAL_PKI_CA_CERT_FILE      = "/etc/ipsec.d/certs/external/ca-cert.pem"
EXTERNAL_PKI_SERVER_CERT_FILE  = "/etc/ipsec.d/certs/external/vpn-server-cert.pem"
EXTERNAL_PKI_SERVER_KEY_FILE   = "/etc/ipsec.d/private/external/vpn-server-key.pem"

IPSEC_CONF_PATH       = "/etc/ipsec.conf"


# ---------------------------------------------------------------------------------------------------------------------

# line used to separate blocks of information in the log
SEPARATOR_LINE = "----------------------------------------------------------------------------------------------------------------------"

# ---------------------------------------------------------------------------------------------------------------------


# name of the service
service_name = "strongswan"

# determines whether the service is run by the startup script
enabled = True

def get_service():
    "Returns an instance of the service provided by the service plugin."
    return StrongSwan()


# ---------------------------------------------------------------------------------------------------------------------


class StrongSwan(Service):

    def prepare(self):
        """
        Reads environment variables and checks preconditions the following call to configure() needs to succeed. In case
        of anything being screwed in the configuration or system, this method should throw an exception to abort starting
        up before configure() modifies any configuration files.
        """

        pass

    # ---------------------------------------------------------------------------------------------------------------------

    def configure(self):
        """
        Creates/modifies the configuration file according to environment variables.
        """

        # read settings in environment variables
        # -----------------------------------------------------------------------------------------
        self._use_internal_pki = get_env_setting_bool("USE_INTERNAL_PKI", True)
        self._vpn_hostname = get_env_setting_bool("VPN_HOSTNAME", gethostname())


        # create directories
        # -----------------------------------------------------------------------------------------
        os.makedirs(os.path.dirname(INTERNAL_PKI_CA_CERT_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(INTERNAL_PKI_CA_KEY_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(INTERNAL_PKI_SERVER_CERT_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(INTERNAL_PKI_SERVER_KEY_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(EXTERNAL_PKI_CA_CERT_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(EXTERNAL_PKI_SERVER_CERT_FILE), exist_ok = True);
        os.makedirs(os.path.dirname(EXTERNAL_PKI_SERVER_KEY_FILE), exist_ok = True);

        # setup cryptographic stuff
        # -----------------------------------------------------------------------------------------
        if self._use_internal_pki:
            self.init_pki_internal()
        else:
            self.init_pki_external();


        # generate ipsec.conf
        # -----------------------------------------------------------------------------------------

#        with open(IPSEC_CONF_PATH, "wt") as f:
#            f.write('config setup\n')
#            f.write('    charondebug="ike 1, knl 1, cfg 0"\n')
#            f.write('    uniqueids=no\n')
#            f.write('\n')
#            f.write('conn ikev2-vpn\n')
#            f.write('    auto=add\n')
#            f.write('    compress=no\n')
#            f.write('    type=tunnel\n')
#            f.write('    keyexchange=ikev2\n')
#            f.write('    fragmentation=yes\n')
#            f.write('    forceencaps=yes\n')
#            f.write('    ike=aes256-sha1-modp1024,3des-sha1-modp1024!\n')
#            f.write('    esp=aes256-sha1,3des-sha1!\n')
#            f.write('    dpdaction=clear\n')
#            f.write('    dpddelay=300s\n')
#            f.write('    rekey=no\n')
#            f.write('    left=%any\n')
#            f.write('    leftid=@server_name_or_ip\n')
#            f.write('    leftcert=/data/ssl/vpn-server-cert.pem\n')
#            f.write('    leftsendcert=always\n')
#            f.write('    leftsubnet=0.0.0.0/0\n')
#            f.write('    right=%any\n')
#            f.write('    rightid=%any\n')
#            f.write('    rightauth=eap-mschapv2\n')
#            f.write('    rightdns=8.8.8.8,8.8.4.4\n')
#            f.write('    rightsourceip=10.10.10.0/24\n')
#            f.write('    rightsendcert=never\n')
#            f.write('    eap_identity=%identity\n')

    # ---------------------------------------------------------------------------------------------------------------------

    def init_pki_internal(self):
        """
        Initializes the internal Public-Key Infrastructure (PKI) and loads/generates the appropriate keys and certificates
        needed to run the VPN server.
        """

        # check server key
        # -----------------------------------------------------------------------------------------
        create_server_key = False
        if os.path.exists(INTERNAL_PKI_SERVER_KEY_FILE):
            Log.write_note("Loading key of the VPN server ({0})...".format(INTERNAL_PKI_SERVER_KEY_FILE))
            with open(INTERNAL_PKI_SERVER_KEY_FILE, "rt") as f: key = f.read()
            self._server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        else:
            Log.write_note("The key of the VPN server ({0}) does not exist.".format(INTERNAL_PKI_SERVER_KEY_FILE))
            create_server_key = True

        # check server certificate and whether it needs to be (re)generated
        # -----------------------------------------------------------------------------------------
        create_server_cert = False
        if create_server_key:

           if os.path.exists(INTERNAL_PKI_SERVER_CERT_FILE):

               Log.write_note("Loading certificate of the VPN server ({0})...".format(INTERNAL_PKI_SERVER_CERT_FILE))
               with open(INTERNAL_PKI_SERVER_CERT_FILE, "rt") as f: cert = f.read()
               self._server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

               # check whether the hostname is correct
               cert_hostname = self._server_cert.get_subject().CN
               if self._vpn_hostname != cert_hostname:
                   Log.write_warning("The certificate was made for '{0}', but the '{1}' is currently configured.".format(cert_hostname, self._vpn_hostname))
                   Log.write_warning("Fixing this automatically by regenerating the server certificate.")
                   create_server_cert = True

           else:
                Log.write_note("The certificate of the VPN server ({0}) does not exist.".format(INTERNAL_PKI_SERVER_CERT_FILE))
                create_server_cert = True

        else:
            Log.write_note("The key is generated, so the certificate of the VPN server ({0}) needs to be generated as well.".format(INTERNAL_PKI_SERVER_CERT_FILE))
            create_server_cert = True

        # generate server key/certificate using the integrated certificate authority, if necessary
        # -----------------------------------------------------------------------------------------
        if create_server_key or create_server_cert:

            Log.write_note("Preparing Internal CA to create the key/certificate of the VPN server...")

            # abort, if the certificate of the internal CA is present, but the key is not
            # (most probably the user has removed the key for security reasons)
            # => abort initialization, the user must provide the key or delete the CA certificate as well
            # ---------------------------------------------------------------------
            ca_key_exists = os.path.exists(INTERNAL_PKI_CA_KEY_FILE)
            ca_cert_exists = os.path.exists(INTERNAL_PKI_CA_CERT_FILE)
            if ca_cert_exists and not ca_key_exists:
                raise RuntimeError(("The certificate of the internal CA exists, but the key does not.\n"
                                    "Cannot generate key/certificate for the VPN server without it.\n"
                                    "Please provide the key ({0}) and retry.").format(INTERNAL_PKI_CA_KEY_FILE));

            # load/create the CA key
            # ---------------------------------------------------------------------
            if ca_key_exists:
                Log.write_note("Loading key of the internal CA ({0})...".format(INTERNAL_PKI_CA_KEY_FILE))
                with open(INTERNAL_PKI_CA_KEY_FILE, "rt") as f: key = f.read()
                self._ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
            else:
                Log.write_note("The key of the internal CA ({0}) does not exist. Generating...".format(INTERNAL_PKI_CA_KEY_FILE))
                self._ca_key = crypto.PKey()
                self._ca_key.generate_key(crypto.TYPE_RSA, 4096)
                with open(INTERNAL_PKI_CA_KEY_FILE, "wb") as f:
                    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self._ca_key))
                os.chown(INTERNAL_PKI_CA_KEY_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_CA_KEY_FILE, S_IRUSR | S_IWUSR)
                Log.write_note("The key of the internal CA was generated successfully.")

            # load/create the CA certificate
            # ---------------------------------------------------------------------
            if ca_cert_exists:
                Log.write_note("Loading certificate of the internal CA ({0})...".format(INTERNAL_PKI_CA_CERT_FILE))
                with open(INTERNAL_PKI_CA_CERT_FILE, "rt") as f: cert = f.read()
                self._ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            else:
                Log.write_note("The certificate of the internal CA ({0}) does not exist. Generating...".format(INTERNAL_PKI_CA_CERT_FILE))
                self._ca_cert = crypto.X509()
                self._ca_cert.get_subject().C  = "DE"
                self._ca_cert.get_subject().ST = "Berlin"
                self._ca_cert.get_subject().L  = "Berlin"
                self._ca_cert.get_subject().O  = "CloudyCube"
                self._ca_cert.get_subject().CN = "Internal CA for VPN"
                self._ca_cert.set_serial_number(1)
                self._ca_cert.gmtime_adj_notBefore(0)
                self._ca_cert.gmtime_adj_notAfter(10*365*24*60*60)
                self._ca_cert.set_issuer(self._ca_cert.get_subject())
                self._ca_cert.set_pubkey(self._ca_key)
                self._ca_cert.add_extensions([
                    crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
                    crypto.X509Extension(b'keyUsage', True, b'keyCertSign, cRLSign')
                ])
                self._ca_cert.sign(self._ca_key, "sha256")
                with open(INTERNAL_PKI_CA_CERT_FILE, "wb") as f:
                   f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self._ca_cert))
                os.chown(INTERNAL_PKI_CA_CERT_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_CA_CERT_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
                Log.write_note("The certificate of the internal CA was generated successfully.")

            # load/create the server key
            # ---------------------------------------------------------------------
            if create_server_key:
                Log.write_note("Generating the key of the VPN server ({0})...".format(INTERNAL_PKI_SERVER_KEY_FILE))
                self._server_key = crypto.PKey()
                self._server_key.generate_key(crypto.TYPE_RSA, 2048)
                with open(INTERNAL_PKI_SERVER_KEY_FILE, "wb") as f:
                    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self._server_key))
                os.chown(INTERNAL_PKI_SERVER_KEY_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_KEY_FILE, S_IRUSR | S_IWUSR)
                Log.write_note("The key of the VPN server was generated successfully.")

            # load/create the server certificate
            # ---------------------------------------------------------------------
            if create_server_cert:
                Log.write_note("Generating the certificate of the VPN server ({0})...".format(INTERNAL_PKI_SERVER_CERT_FILE))
                self._server_cert = crypto.X509()
                self._server_cert.get_subject().C  = "DE"
                self._server_cert.get_subject().ST = "Berlin"
                self._server_cert.get_subject().L  = "Berlin"
                self._server_cert.get_subject().O  = "CloudyCube"
                self._server_cert.get_subject().OU = "VPN Provider"
                self._server_cert.get_subject().CN = self._vpn_hostname
                self._server_cert.set_serial_number(1)
                self._server_cert.gmtime_adj_notBefore(0)
                self._server_cert.gmtime_adj_notAfter(10*365*24*60*60)
                self._server_cert.set_issuer(self._ca_cert.get_subject())
                self._server_cert.set_pubkey(self._server_key)
                self._server_cert.add_extensions(
                [
                    # basicConstraints
                    # -------------------------------------------------------------------------------------
                    crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),

                    # keyUsage
                    # -------------------------------------------------------------------------------------
                    crypto.X509Extension(b'keyUsage', False, b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement'),

                    # extendedKeyUsage
                    # -------------------------------------------------------------------------------------
                    # serverAuth (1.3.6.1.5.5.7.3.1) is required by the built-in Windows 7 VPN client
                    # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
                    # -------------------------------------------------------------------------------------
                    crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, 1.3.6.1.5.5.8.2.2')
                ])
                self._server_cert.sign(self._ca_key, "sha256")
                with open(INTERNAL_PKI_SERVER_CERT_FILE, "wb") as f:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self._server_cert))
                os.chown(INTERNAL_PKI_SERVER_CERT_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_CERT_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
                Log.write_note("The certificate of the VPN server was generated successfully.")
        else:
            # the server key/certificate exists already
            pass

        # log the certificate of the VPN server
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, self._server_cert).decode('utf-8')
        Log.write_note("Certificate of the VPN server\n{1}\n{0}\n{1}".format(dump, SEPARATOR_LINE))

    # ---------------------------------------------------------------------------------------------------------------------

    def init_pki_external(self):
        """
        """

        pass
