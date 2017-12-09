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
from subprocess import run, DEVNULL
from ..cc_helpers import read_text_file, write_text_file, replace_php_define, replace_php_variable, generate_password, get_env_setting_bool, get_env_setting_integer, get_env_setting_string
from ..cc_log import Log
from ..cc_service import Service
from .cc_ca import CertificateAuthority

# ---------------------------------------------------------------------------------------------------------------------

# keys/certificates for use in production environments
EXTERNAL_PKI_BASE_DIR          = "/data/external_ca"
EXTERNAL_PKI_CA_CERT_FILE      = os.path.join(EXTERNAL_PKI_BASE_DIR, "ca-cert.pem")
EXTERNAL_PKI_SERVER_CERT_FILE  = os.path.join(EXTERNAL_PKI_BASE_DIR, "server", "cert.pem")
EXTERNAL_PKI_SERVER_KEY_FILE   = os.path.join(EXTERNAL_PKI_BASE_DIR, "server", "key.pem")

# configuration files
IPSEC_CONF_PATH                = "/etc/ipsec.conf"


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

        # read settings in environment variables
        # -----------------------------------------------------------------------------------------
        self._use_internal_pki = get_env_setting_bool("USE_INTERNAL_PKI", True)
        self._vpn_hostnames = get_env_setting_string("VPN_HOSTNAMES", gethostname()).split(",")


    # ---------------------------------------------------------------------------------------------------------------------


    def configure(self):
        """
        Creates/modifies the configuration file according to environment variables.
        """

        # setup cryptographic stuff
        # -----------------------------------------------------------------------------------------
        if self._use_internal_pki:
            self.init_pki_internal()
        else:
            self.init_pki_external();


        # generate ipsec.conf
        # -----------------------------------------------------------------------------------------

        with open(IPSEC_CONF_PATH, "wt") as f:
            f.write("config setup\n")
            f.write("    charondebug=\"ike 3, knl 3, cfg 3, net 3, esp 3, dmn 3,  mgr 3\"\n")
            f.write("\n")
            f.write("ca strongswan\n")
            f.write("    cacert=/data/internal_ca/ca-cert.pem\n")
#            f.write("    certuribase=http://ip6-winnetou.strongswan.org/certs/\n")
#            f.write("    crluri=http://ip6-winnetou.strongswan.org/strongswan.crl\n")
            f.write("    auto=add\n")
            f.write("\n")
            f.write("conn %default\n")
            f.write("    keyexchange=ikev2\n")
            f.write("    dpdaction=clear\n")
            f.write("    dpddelay=300s\n")
            f.write("    authby=pubkey\n");
#            f.write("    fragmentation=yes\n")
#            f.write("    forceencaps=yes\n")
            f.write("    rekey=no\n")
            f.write("    left=%any\n")
            f.write("    leftid=@{0}\n".format(self._vpn_hostnames[0]))
            f.write("    leftsubnet=0.0.0.0/0\n")
#            f.write("    leftsubnet=192.168.10.0/24\n")
            f.write("    leftcert=/data/internal_ca/server/cert.pem\n")
            f.write("    leftsendcert=always\n")
            f.write("    leftfirewall=yes\n")
            f.write("    right=%any\n")
            f.write("    rightsourceip=10.10.10.10/24\n")
            f.write("    rightdns=8.8.8.8\n") # durch container dns ersetzen

#            f.write("conn IKEv2-Pubkey\n")
#            f.write("    leftauth=pubkey\n")
#            f.write("    rightauth=pubkey\n")
#            f.write("    leftsendcert=always\n")
#            f.write("    rightsendcert=always\n")
#            f.write("   auto=add\n")

            f.write("conn IKEv2-EAP\n")
            f.write("    eap_identity=%any\n")
            f.write("    rightauth=eap-dynamic\n")

            f.write("conn IKEv2-EAP-TLS\n")
            f.write("    eap_identity=%any\n")
            f.write("    leftauth=pubkey\n")
            f.write("    rightauth=eap-tls\n")
            f.write("    rightsendcert=never\n")
            f.write("    auto=add\n")

        # configure networking
        # -----------------------------------------------------------------------------------------

        Log.write_note("Configuring networking...")

        Log.write_note("=> IPv4: Enabling forwarding")
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, stdout=DEVNULL)

        Log.write_note("=> IPv4: Enabling masquerading")
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.10.10.0/24", "-o", "eth0", "-m", "policy", "--dir", "out", "--pol", "ipsec", "-j", "ACCEPT"], check=True, stdout=DEVNULL)
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.10.10.0/24", "-o", "eth0", "-j", "MASQUERADE"], check=True, stdout=DEVNULL)


    # ---------------------------------------------------------------------------------------------------------------------

    def init_pki_internal(self):
        """
        Initializes the internal Public-Key Infrastructure (PKI) and loads/generates the appropriate keys and certificates
        needed to run the VPN server.
        """

        ca = CertificateAuthority()

        # get the key/certificate of the VPN server (create it, if necessary)
        sans = [ "DNS:" + s for s in self._vpn_hostnames  ]
        vpn_server_data = ca.get_vpn_server_data(sans)
        self._server_key = vpn_server_data["key"]
        self._server_key_path = vpn_server_data["key path"]
        self._server_cert = vpn_server_data["certificate"]
        self._server_cert_path = vpn_server_data["certificate path"]

        # log the certificate of the VPN server
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, self._server_cert).decode('utf-8')
        Log.write_note("Certificate of the VPN server\n{1}\n{0}\n{1}".format(dump, SEPARATOR_LINE))

    # ---------------------------------------------------------------------------------------------------------------------

    def init_pki_external(self):
        """
        """

        pass
