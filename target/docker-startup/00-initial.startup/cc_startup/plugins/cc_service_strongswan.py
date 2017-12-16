"""
This module contains everything needed to configure 'strongswan'.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
import re

from ipaddress import IPv4Network, IPv6Network
from mako.template import Template
from OpenSSL import crypto, SSL
from socket import gethostname
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from subprocess import run, DEVNULL
from ..cc_helpers import read_text_file, write_text_file, replace_php_define, replace_php_variable, generate_password, get_env_setting_bool, get_env_setting_integer, get_env_setting_string, load_kernel_module
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
IPSEC_CONF_PATH                  = "/etc/ipsec.conf"
IPSEC_CONF_TEMPLATE_PATH         = "/etc/ipsec.conf.mako"
IPSEC_SECRETS_PATH               = "/etc/ipsec.secrets"
IPSEC_SECRETS_TEMPLATE_PATH      = "/etc/ipsec.secrets.mako"
STRONGSWAN_CONF_PATH             = "/etc/strongswan.conf"
STRONGSWAN_CONF_TEMPLATE_PATH    = "/etc/strongswan.conf.mako"
NAMED_CONF_OPTIONS_PATH          = "/etc/bind/named.conf.options"
NAMED_CONF_OPTIONS_TEMPLATE_PATH = "/etc/bind/named.conf.options.mako"

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
        self._use_internal_pki                 = get_env_setting_bool("USE_INTERNAL_PKI", True)
        self._vpn_hostnames                    = get_env_setting_string("VPN_HOSTNAMES", gethostname())
        self._client_subnet_ipv4               = get_env_setting_string("CLIENT_SUBNET_IPV4", "10.0.0.0/24")
        self._use_docker_dns                   = get_env_setting_bool("USE_DOCKER_DNS", False)

        if self._use_docker_dns:
            self._dns_servers = "127.0.0.11"
        else:
            self._dns_servers = get_env_setting_string("DNS SERVERS", "8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844")

        self._allow_internet_access            = get_env_setting_bool("ALLOW_INTERNET_ACCESS", True)
        self._allow_inter_client_communication = get_env_setting_bool("ALLOW_INTER_CLIENT_COMMUNICATION", False)

        # split up hostnames
        self._vpn_hostnames = [ s.strip() for s in self._vpn_hostnames.split(",") ]

        # split up DNS servers
        self._dns_servers = [ s.strip() for s in self._dns_servers.split(",") ]

        # load af_key module is loaded (kernel support for IPSec)
        load_kernel_module("af_key")


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

        # determine the start and the end of the client ip range
        # (the first address becomes the IP of the VPN server itself)
        # -----------------------------------------------------------------------------------------
        client_subnet_ipv4 = IPv4Network(self._client_subnet_ipv4)
        for (index, host_ip) in enumerate(client_subnet_ipv4.hosts()):
            if index == 0:
                self._own_ip_in_client_subnet_ipv4 = str(host_ip)
            elif index == 1:
                self._client_ip_range_start_ipv4 = str(host_ip)
            else:
                self._client_ip_range_end_ipv4 = str(host_ip)

        # prepare context for the template engine that will generate strongswan.conf and ipsec.conf
        # -----------------------------------------------------------------------------------------
        template_context = {
          "ca_key_path"                    : self._ca_key_path,
          "ca_cert_path"                   : self._ca_cert_path,
          "server_key_path"                : self._server_key_path,
          "server_cert_path"               : self._server_cert_path,
          "dns_servers"                    : self._dns_servers,
          "client_subnet_ipv4"             : self._client_subnet_ipv4,
          "client_ip_range_start_ipv4"     : self._client_ip_range_start_ipv4,
          "client_ip_range_end_ipv4"       : self._client_ip_range_end_ipv4,
          "own_ip_in_client_subnet_ipv4"   : self._own_ip_in_client_subnet_ipv4
        }

        # generate strongswan.conf
        # -----------------------------------------------------------------------------------------
        rendered = Template(filename = STRONGSWAN_CONF_TEMPLATE_PATH).render(**template_context)
        with open(STRONGSWAN_CONF_PATH, "wt") as f:
            f.write(rendered)

        # generate ipsec.conf
        # -----------------------------------------------------------------------------------------
        rendered = Template(filename = IPSEC_CONF_TEMPLATE_PATH).render(**template_context)
        with open(IPSEC_CONF_PATH, "wt") as f:
            f.write(rendered)

        # generate ipsec.secrets
        # -----------------------------------------------------------------------------------------
        rendered = Template(filename = IPSEC_SECRETS_TEMPLATE_PATH).render(**template_context)
        with open(IPSEC_SECRETS_PATH, "wt") as f:
            f.write(rendered)

        # generate bind.conf.options
        # -----------------------------------------------------------------------------------------
        rendered = Template(filename = NAMED_CONF_OPTIONS_TEMPLATE_PATH).render(**template_context)
        with open(NAMED_CONF_OPTIONS_PATH, "wt") as f:
            f.write(rendered)

        # configure networking
        # -----------------------------------------------------------------------------------------

        Log.write_note("Configuring networking...")

        # add a dummy device with an ip address for the vpn server in the client network
        run(["ip", "link", "add", "type", "dummy"], check=True, stdout=DEVNULL)
        run(["ip", "addr", "add", self._own_ip_in_client_subnet_ipv4, "dev", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "link", "set", "up", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "route", "add", self._own_ip_in_client_subnet_ipv4, "dev", "dummy0"], check=True, stdout=DEVNULL)

        # enable forwarding
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, stdout=DEVNULL)

        # do not accept ICMP redirects (prevent MITM attacks)
        run(["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"], check=True, stdout=DEVNULL)

        # do not send ICMP redirects (we are not a router that should redirect others)
        run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], check=True, stdout=DEVNULL)

        # disable Path MTU discovery to prevent packet fragmentation problems
        # run(["sysctl", "-w", "net.ipv4.ip_no_pmtu_disc=1"], check=True, stdout=DEVNULL)

        # -----------------------------------------------------------------------------------------

        Log.write_note("=> IPv4: Configuring firewall for incoming connections")

        # allow localhost to access everything
        run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # allow packets that belong to self-initiated connections
        run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # allow IPSec related traffic
        run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", "500",  "-j", "ACCEPT"], check=True, stdout=DEVNULL)
        run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", "4500", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # allow VPN clients to access the DNS server
        run(["iptables", "-A", "INPUT", "-p", "udp", "--source", self._client_subnet_ipv4, "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec", "--proto", "esp", "-j", "ACCEPT"], check=True, stdout=DEVNULL)
        run(["iptables", "-A", "INPUT", "-p", "tcp", "--source", self._client_subnet_ipv4, "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec", "--proto", "esp", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # drop everything else
        run(["iptables", "-A", "INPUT", "-j", "DROP"], check=True, stdout=DEVNULL)

        # -----------------------------------------------------------------------------------------

        Log.write_note("=> IPv4: Configuring firewall for routing")

        # let packets that belong to existing connections pass
        run(["iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"], check=True, stdout=DEVNULL)
        run(["iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # block packets between VPN clients (if requested)
        if not self._allow_inter_client_communication:
            run(["iptables", "-A", "FORWARD", "-s", self._client_subnet_ipv4, "-d", self._client_subnet_ipv4, "-j", "DROP"], check=True, stdout=DEVNULL)

        # let IPSec packets to/from clients pass
        run(["iptables", "-A", "FORWARD", "-i", "eth0", "-o", "eth0", "-s", self._client_subnet_ipv4, "-m", "policy", "--dir", "in", "--pol", "ipsec", "--proto", "esp", "-j", "ACCEPT"], check=True, stdout=DEVNULL)
        run(["iptables", "-A", "FORWARD", "-i", "eth0", "-o", "eth0", "-d", self._client_subnet_ipv4, "-m", "policy", "--dir", "out", "--pol", "ipsec", "--proto", "esp", "-j", "ACCEPT"], check=True, stdout=DEVNULL)

        # Reduce the size of tcp packets by adjusting the packets' maximum segment size to prevent IP packet fragmentation on some clients
        # This prevents issues with some VPN clients, but it is an evil workaround (google 'MSS Clamping' for details)
#        run(["iptables", "-t", "mangle", "-A", "FORWARD",
#            "--match", "policy", "--dir", "in", "--pol", "ipsec", "-s", self._client_subnet_ipv4, "-o", "eth0",
#            "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "tcpmss", "--mss", "1361:1536",
#            "-j", "TCPMSS", "--set-mss", "1360"], check=True, stdout=DEVNULL)

        # drop all packets that did not match one of the preceding rules
        run(["iptables", "-A", "FORWARD", "-j", "DROP"], check=True, stdout=DEVNULL)

        # configure masquerading to allow clients to access the internet, if requested
        if self._allow_internet_access:
            Log.write_note("=> IPv4: Enabling masquerading")
            run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", self._client_subnet_ipv4, "-o", "eth0", "-m", "policy", "--dir", "out", "--pol", "ipsec", "-j", "ACCEPT"], check=True, stdout=DEVNULL)
            run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", self._client_subnet_ipv4, "-o", "eth0", "-j", "MASQUERADE"], check=True, stdout=DEVNULL)


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

        self._server_key       = vpn_server_data["key"]
        self._server_key_path  = vpn_server_data["key path"]
        self._server_cert      = vpn_server_data["certificate"]
        self._server_cert_path = vpn_server_data["certificate path"]
        self._ca_key           = ca.ca_key
        self._ca_key_path      = ca.ca_key_path
        self._ca_cert          = ca.ca_cert
        self._ca_cert_path     = ca.ca_cert_path

        # log the certificate of the VPN server
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, self._server_cert).decode('utf-8')
        Log.write_note("Certificate of the VPN server\n{1}\n{0}\n{1}".format(dump, SEPARATOR_LINE))

    # ---------------------------------------------------------------------------------------------------------------------

    def init_pki_external(self):
        """
        """

        pass
