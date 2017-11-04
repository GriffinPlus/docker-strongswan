"""
This module contains everything related to the internal certificate authority of the VPN server.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os

from OpenSSL import crypto, SSL
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from ..cc_log import Log


# ---------------------------------------------------------------------------------------------------------------------


class CertificateAuthority:

    # -------------------------------------------------------------------------------------------

    def __init__(self, base_dir):

        self._base_dir     = base_dir
        self._ca_cert_path = os.path.join(base_dir, "certs",   "ca-cert.pem")
        self._ca_key_path  = os.path.join(base_dir, "private", "ca-key.pem")

    # -------------------------------------------------------------------------------------------

    def init_ca(self, need_key):
        """
        Initializes the CA loading/creating any related data.
        
        Args:
            need_key (bool): True, if the caller needs the private key of the CA for its operation;
                             False, if the caller only needs the public key of the CA for its operation.
        """

        # create directories where the key/certificate of the CA are stored, if necessary
        # ---------------------------------------------------------------------
        os.makedirs(os.path.dirname(self._ca_cert_path), exist_ok = True);
        os.makedirs(os.path.dirname(self._ca_key_path),  exist_ok = True);

        # abort, if the certificate of the CA is present, but the key is not
        # (most probably the user has removed the key for security reasons)
        # => abort initialization, the user must provide the key or delete the CA certificate as well
        # ---------------------------------------------------------------------
        ca_key_exists = os.path.exists(self._ca_key_path)
        ca_cert_exists = os.path.exists(self._ca_cert_path)
        if ca_cert_exists and need_key and not ca_key_exists:
            raise RuntimeError(("The certificate of the CA exists, but the key does not.\n"
                                "Cannot perform requested operation without the key.\n"
                                "Please provide the key ({0}) and retry.").format(self._ca_key_path));

        # load/create the CA key
        # ---------------------------------------------------------------------
        if ca_key_exists:
            Log.write_note("Loading key of the CA ({0})...".format(self._ca_key_path))
            with open(self._ca_key_path, "rt") as f: key = f.read()
            self._ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        else:
            Log.write_note("The key of the CA ({0}) does not exist. Generating...".format(self._ca_key_path))
            self._ca_key = crypto.PKey()
            self._ca_key.generate_key(crypto.TYPE_RSA, 4096)
            with open(self._ca_key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self._ca_key))
            os.chown(self._ca_key_path, 0, 0)
            os.chmod(self._ca_key_path, S_IRUSR | S_IWUSR)
            Log.write_note("The key of the CA was generated successfully.")

        # load/create the CA certificate
        # ---------------------------------------------------------------------
        if ca_cert_exists:
            Log.write_note("Loading certificate of the CA ({0})...".format(self._ca_cert_path))
            with open(self._ca_cert_path, "rt") as f: cert = f.read()
            self._ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        else:
            Log.write_note("The certificate of the CA ({0}) does not exist. Generating...".format(self._ca_cert_path))
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
            with open(self._ca_cert_path, "wb") as f:
               f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self._ca_cert))
            os.chown(self._ca_cert_path, 0, 0)
            os.chmod(self._ca_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
            Log.write_note("The certificate of the CA was generated successfully.")


    # -------------------------------------------------------------------------------------------


    def get_vpn_server_data(self, vpn_hostnames):
        """
        Gets the key/certificate and related data of the VPN server, creates the certificate, if necessary.

        Args:
            vpn_hostnames (tuple,list): Hostnames and IP addresses the VPN server will be reachable via.
                                        Please prefix hostnames with 'DNS:' and IP addresses with 'IP:'
                                        The first hostname/IP address in the list is put into the Common Name(CN) of the certificate.
                                        All hostnames/IP addresses are put into the X.509 'subjectAltName' extension.

        Returns:
            A dictionary containing data about the key/certificate of the VPN server.
            The dictionary contains the following data:
            - 'key'                 (obj)  : OpenSSL key object
            - 'key path'            (str)  : Full path of the key file on disk
            - 'key created'         (bool) : True, if the key was created;
                                             False, if the existing key was loaded
            - 'certificate'         (obj)  : OpenSSL certificate object
            - 'certificate path'    (str)  : Full path of the certificate file on disk
            - 'certificate created' (bool) : True, if the certificate was created;
                                             False, if the existing certificate was loaded
            
        """

        server_cert_path = os.path.join(self._base_dir, "certs",   "server-cert.pem")
        server_key_path  = os.path.join(self._base_dir, "private", "server-key.pem")

        # check server key
        # -----------------------------------------------------------------------------------------
        create_server_key = False
        if os.path.exists(server_key_path):
            Log.write_note("Loading key of the VPN server ({0})...".format(server_key_path))
            with open(server_key_path, "rt") as f: key = f.read()
            server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        else:
            Log.write_note("The key of the VPN server ({0}) does not exist.".format(server_key_path))
            create_server_key = True

        # check server certificate and whether it needs to be (re)generated
        # -----------------------------------------------------------------------------------------
        create_server_cert = False
        if create_server_key:

           if os.path.exists(server_cert_path):

               Log.write_note("Loading certificate of the VPN server ({0})...".format(server_cert_path))
               with open(server_cert_path, "rt") as f: cert = f.read()
               server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

               # check whether the hostname is correct
               # TODO: check multiple hostnames/IPs in SANs
               cert_hostname = server_cert.get_subject().CN
               if vpn_hostnames[0] != cert_hostname:
                   Log.write_warning("The certificate was made for '{0}', but the '{1}' is currently configured.".format(cert_hostname, vpn_hostname))
                   Log.write_warning("Fixing this automatically by regenerating the server certificate.")
                   create_server_cert = True

           else:
                Log.write_note("The certificate of the VPN server ({0}) does not exist.".format(server_cert_path))
                create_server_cert = True

        else:
            Log.write_note("The key is generated, so the certificate of the VPN server ({0}) needs to be generated as well.".format(server_cert_path))
            create_server_cert = True


        # initialize the CA, if a new certificate is about to be created
        # ---------------------------------------------------------------------
        if create_server_cert:
            self.init_ca(True)

        # load/create the server key
        # ---------------------------------------------------------------------
        if create_server_key:
            Log.write_note("Generating the key of the VPN server ({0})...".format(server_key_path))
            server_key = crypto.PKey()
            server_key.generate_key(crypto.TYPE_RSA, 4096)
            with open(server_key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))
            os.chown(server_key_path, 0, 0)
            os.chmod(server_key_path, S_IRUSR | S_IWUSR)
            Log.write_note("The key of the VPN server was generated successfully.")

        # load/create the server certificate
        # ---------------------------------------------------------------------
        if create_server_cert:
            Log.write_note("Generating the certificate of the VPN server ({0})...".format(server_cert_path))
            server_cert = crypto.X509()
            server_cert.get_subject().C  = "DE"
            server_cert.get_subject().ST = "Berlin"
            server_cert.get_subject().L  = "Berlin"
            server_cert.get_subject().O  = "CloudyCube"
            server_cert.get_subject().OU = "VPN Provider"
            server_cert.get_subject().CN = ":".join(vpn_hostnames[0].split(":")[1:]) # strips the "DNS:" or "IP:" prefix
            server_cert.set_serial_number(1)
            server_cert.gmtime_adj_notBefore(0)
            server_cert.gmtime_adj_notAfter(10*365*24*60*60)
            server_cert.set_issuer(self._ca_cert.get_subject())
            server_cert.set_pubkey(server_key)
            server_cert.add_extensions(
            [
                # basicConstraints
                # -------------------------------------------------------------------------------------
                crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),

                # keyUsage
                # -------------------------------------------------------------------------------------
                crypto.X509Extension(b'keyUsage', False, b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement'),

                # subjectAltName
                # -------------------------------------------------------------------------------------
                crypto.X509Extension(b"subjectAltName", False, ", ".join(vpn_hostnames).encode()),

                # extendedKeyUsage
                # -------------------------------------------------------------------------------------
                # serverAuth (1.3.6.1.5.5.7.3.1) is required by the built-in Windows 7 VPN client
                # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
                # -------------------------------------------------------------------------------------
                crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, 1.3.6.1.5.5.8.2.2')
            ])
            server_cert.sign(self._ca_key, "sha256")
            with open(server_cert_path, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
            os.chown(server_cert_path, 0, 0)
            os.chmod(server_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
            Log.write_note("The certificate of the VPN server was generated successfully.")
 
        return {
            "key"                 : server_key,
            "key path"            : server_key_path,
            "key created"         : create_server_key,
            "certificate"         : server_cert,
            "certificate path"    : server_cert_path,
            "certificate created" : create_server_cert
        }

    # -------------------------------------------------------------------------------------------

    def get_client_data(self, identity):
        """

        """

        return {

        }
