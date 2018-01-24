"""
This module contains the command processing plugin handling VPN related commands.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
import shutil
import socket
import sys

from datetime import datetime
from OpenSSL import crypto
from mako.template import Template
from netaddr import IPAddress, IPNetwork, AddrFormatError
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from subprocess import run, DEVNULL

from ..cc_log import Log
from ..cc_cmdproc import CommandProcessor, PositionalArgument, NamedArgument
from ..cc_errors import ExitCodeError, FileNotFoundError, GeneralError, CommandLineArgumentError, IoError, EXIT_CODE_SUCCESS
from ..cc_helpers import read_text_file, write_text_file, print_error, readline_if_no_tty, \
                         get_env_setting_bool, get_env_setting_integer, get_env_setting_string, \
                         iptables_run, iptables_add, ip6tables_run, ip6tables_add, \
                         does_mount_point_exist, is_mount_point_readonly, \
                         load_kernel_module, resolve_hostnames, \
                         is_email_address
from . import cc_ca


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Command Processor Plugin Interface
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


# name of the processor
processor_name = 'VPN Command Processor'

# determines whether the processor is run by the startup script
enabled = True

def get_processor():
    "Returns an instance of the processor provided by the command processor plugin."
    return VpnCommandProcessor()


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Definitions
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


# line used to separate blocks of information in the log
SEPARATOR_LINE = "----------------------------------------------------------------------------------------------------------------------"

# configuration files
IPSEC_CONF_PATH                  = "/etc/ipsec.conf"
IPSEC_CONF_TEMPLATE_PATH         = "/etc/ipsec.conf.mako"
IPSEC_SECRETS_PATH               = "/etc/ipsec.secrets"
IPSEC_SECRETS_TEMPLATE_PATH      = "/etc/ipsec.secrets.mako"
STRONGSWAN_CONF_PATH             = "/etc/strongswan.conf"
STRONGSWAN_CONF_TEMPLATE_PATH    = "/etc/strongswan.conf.mako"
NAMED_CONF_OPTIONS_PATH          = "/etc/bind/named.conf.options"
NAMED_CONF_OPTIONS_TEMPLATE_PATH = "/etc/bind/named.conf.options.mako"
NDPPD_CONF_PATH                  = "/etc/ndppd.conf"
NDPPD_CONF_TEMPLATE_PATH         = "/etc/ndppd.conf.mako"
SUPERVISORD_NDPPD_CONF_PATH      = "/etc/supervisor/conf.d/ndppd.conf"

# path of the data output directory
OUTPUT_DIRECTORY = "/data-out"

# paths of keys/certificates, when an external CA is used
EXTERNAL_PKI_BASE_DIR          = "/data/external_ca"
EXTERNAL_PKI_CA_CERT_FILE      = os.path.join(EXTERNAL_PKI_BASE_DIR, "ca-cert.crt")
EXTERNAL_PKI_SERVER_CERT_FILE  = os.path.join(EXTERNAL_PKI_BASE_DIR, "server.crt")
EXTERNAL_PKI_SERVER_KEY_FILE   = os.path.join(EXTERNAL_PKI_BASE_DIR, "server.key")

# paths of keys/certificates, when the internal CA is used
INTERNAL_PKI_BASE_DIR          = "/data/internal_ca"
INTERNAL_PKI_SERVER_CERT_FILE  = os.path.join(INTERNAL_PKI_BASE_DIR, "server.crt")
INTERNAL_PKI_SERVER_KEY_FILE   = os.path.join(INTERNAL_PKI_BASE_DIR, "server.key")

# ASN1 datetime format
ASN1_DATETIME_FORMAT = "%Y%m%d%H%M%SZ"

# datetime format used when printing human-readable
TEXT_OUTPUT_DATETIME_FORMAT = "%Y/%m/%d %H:%M:%S (UTC)"

# IP Addresses
IPV6_NETWORK_GUA        = IPNetwork("2000::/3")
IPV6_NETWORK_SITE_LOCAL = IPNetwork("fc00::/7")

# exit codes
EXIT_CODE_CA_NOT_INITIALIZED            =  10 # The CA is not initialized
EXIT_CODE_CA_ALREADY_INITIALIZED        =  11 # The CA is already initialized
EXIT_CODE_CA_INCONSISTENCY_DETECTED     =  12 # The CA has detected an inconsistency in its database
EXIT_CODE_PASSWORD_REQUIRED             =  20 # The operation requires a password
EXIT_CODE_PASSWORD_WRONG                =  21 # The specified password is wrong
EXIT_CODE_OUTPUT_DIRECTORY_MOUNT_ERROR  =  22 # The data output directory is not mounted correctly


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exceptions
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


class OutputDirectoryMountError(ExitCodeError):
    """
    Exception that is raised, if the data output directory is not mounted correctly.

    Attributes:
        message (str)  : Explanation of the error.

    """

    def __init__(self):
        raise NotImplementedError("Please use the constructor taking an error message describing what is wrong!")

    def __init__(self, message, *args):
        super(OutputDirectoryMountError, self).__init__(EXIT_CODE_OUTPUT_DIRECTORY_MOUNT_ERROR, message, *args)


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# The Command Processor Plugin Class
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


class VpnCommandProcessor(CommandProcessor):


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __init__(self):

        # let base class perform its initialization
        super().__init__()

        # register command handlers
        self.add_handler(self.run,            PositionalArgument("run"),
                                              NamedArgument("ca-pass", from_stdin=True))

        self.add_handler(self.run,            PositionalArgument("run-and-enter"),
                                              NamedArgument("ca-pass", from_stdin=True))

        self.add_handler(self.init,           PositionalArgument("init"),
                                              NamedArgument("ca-pass", from_stdin=True))

        self.add_handler(self.add_client,     PositionalArgument("add"), PositionalArgument("client"),
                                              NamedArgument("ca-pass", from_stdin=True), NamedArgument("out-format"),
                                              NamedArgument("pkcs12-pass", from_stdin=True), NamedArgument("pkcs12-file"))

        self.add_handler(self.list_clients,   PositionalArgument("list"), PositionalArgument("clients"),
                                              NamedArgument("out-format"))

        self.add_handler(self.disable_client, PositionalArgument("disable"), PositionalArgument("client"),
                                              NamedArgument("ca-pass", from_stdin=True), NamedArgument("out-format"))

        self.add_handler(self.enable_client,  PositionalArgument("enable"), PositionalArgument("client"),
                                              NamedArgument("ca-pass", from_stdin=True), NamedArgument("out-format"))

        # register exception handlers for exceptions raised by the internal CA
        self.add_exception_handler(self.__handle_exceptions, cc_ca.NotInitializedError)
        self.add_exception_handler(self.__handle_exceptions, cc_ca.AlreadyInitializedError)
        self.add_exception_handler(self.__handle_exceptions, cc_ca.PasswordRequiredError)
        self.add_exception_handler(self.__handle_exceptions, cc_ca.InvalidPasswordError)
        self.add_exception_handler(self.__handle_exceptions, cc_ca.InconsistencyDetectedError)


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: init
    # -------------------------------------------------------------------------------------------------------------------------------------


    def init(self, pos_args, named_args):
        """
        Initializes the internal CA environment.

        If the container was run with the flags --interactive and --tty, the handler operates in interactive mode, i.e. the
        user is queried, if some information is missing. The output in this mode is made for humans.

        If the container was run with the flags --interactive, but without --tty, the handler operates in script mode, i.e.
        any data needed for the operation must be specified using command line parameters or piped in via stdin. Input to
        stdin is expected to contain one line: the password of the CA. Although using stdin is a bit more lengthy, it minimizes
        the chance of leaking credentials as passwords are neither visible in the process list nor via the inspection features
        of the docker engine API.


        Args:
            pos_args (tuple)  : Positional command line arguments
                                0 (mandatory) => 'init'
            named_args (dict) : Named command line arguments
                                'ca-pass' => Password to protect CA related data with (empty to disable protection)

        Returns:
            The application's exit code.

        """

        # check positional command line arguments
        if len(pos_args) != 1:
            raise CommandLineArgumentError("Expecting 1 positional argument only, you specified {0} ({1})", len(pos_args), pos_args)

        # evaluate named command line arguments
        ca_pass = named_args["ca-pass"][0] if len(named_args["ca-pass"]) > 0 else None

        # check whether the CA environment is already initialized
        ca = cc_ca.CertificateAuthority()
        if ca.is_inited():
            raise cc_ca.AlreadyInitializedError("The internal CA is already initialized.")

        # query user to enter the password, if it was not specified in the command line
        if ca_pass == None:
            if sys.stdin.isatty():
                ca_pass = input("Please enter the password to protect the CA with: ").strip()
                if len(ca_pass) == 0:
                    print("The password is empty. CA related data is not encrypted!")
            else:
                raise cc_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")

        # initialize the CA environment
        ca.init(ca_pass)

        # success
        print("The CA environment was generated successfully.")
        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: add client
    # -------------------------------------------------------------------------------------------------------------------------------------


    def add_client(self, pos_args, named_args):
        """
        Adds a new client with the specified identity (e-mail address) and protects the generated PKCS12 archive containing
        the client's private key, its certificate and the certificate if the CA with the specified password. The generated
        PKCS12 archive is written into the mounted data output directory. The info written to stdout depends on whether a
        terminal is attached to the container or not.

        If the container was run with the flags --interactive and --tty, the handler operates in interactive mode, i.e. the
        user is queried, if some information is missing. The output in this mode is human-readable prose.

        If the container was run with the flags --interactive, but without --tty, the handler operates in script mode, i.e.
        any data needed for the operation must be specified using command line parameters or piped in via stdin. Input to
        stdin is expected to contain two lines: the password of the CA and the password to use for the PKCS12 file. Although
        using stdin is a bit more lengthy, it minimizes the chance of leaking credentials as passwords are neither visible
        in the process list nor via the inspection features of the docker engine API. The output in the mode is a tab-separated
        record with the following fields:
        - Serial number of the client certificate
        - Path to the generated PKCS12 file (relative to the data output directory)

        Args:
            pos_args (tuple)  : Position encoded command line arguments:
                                0 (mandatory) => 'add'
                                1 (mandatory) => 'client'
                                2 (mandatory) => Identity of the client (e-mail address)
            named_args (dict) : Name encoded command line arguments:
                                'ca-pass'     => The password of the CA
                                'out-format'  => Output type
                                                 'text' => human readable text (default for terminal mode)
                                                 'tsv'  => output optimized for scripting (TSV format, default for script mode)
                                'pkcs12-pass' => The password to protect the created PKCS12 archive with
                                'pkcs12-file' => Name of the file in the data output directory where the PKCS12 file is saved
                                                 (the pattern '<identity> (CSN<10-digit-certificate-serial>' is used, if not specified)

        Returns:
            The application's exit code.

        """

        # evaluate positional command line arguments
        # -----------------------------------------------------------------------------------------
        if len(pos_args) == 3:
            identity = pos_args[2].strip()
        else:
            raise CommandLineArgumentError("Expecting 3 positional arguments, you specified {0} ({1})", len(pos_args), pos_args)

        # check format of the identity
        if not is_email_address(identity):
            raise CommandLineArgumentError("The specified identity ({0}) is not an e-mail address.", identity)

        # perform common handler stuff
        # -----------------------------------------------------------------------------------------
        ca, out_format = self.__prepare_command_handler(pos_args, named_args)
        pkcs12_pass = named_args["pkcs12-pass"][0] if len(named_args["pkcs12-pass"]) > 0 else None
        pkcs12_file = named_args["pkcs12-file"][0] if len(named_args["pkcs12-file"]) > 0 else None

        # ensure that the data output directory is mounted read-write in the container
        # -----------------------------------------------------------------------------------------
        if not os.path.ismount(OUTPUT_DIRECTORY) or is_mount_point_readonly(OUTPUT_DIRECTORY):
            raise OutputDirectoryMountError("The data output directory ({0}) is not mounted read-write in the container.", OUTPUT_DIRECTORY)

        # check whether the specified PKCS12 file is writeable 
        # -----------------------------------------------------------------------------------------
        pkcs12_path = None
        if pkcs12_file:
            pkcs12_path = os.path.normpath(os.path.join(OUTPUT_DIRECTORY, pkcs12_file))
            try:
                with open(pkcs12_path, "w+") as file: pass
            except:
                raise IoError("Opening the specified PKCS12 file for writing failed.")
            os.remove(pkcs12_path)
        
        # query user to enter the password for the PKCS12 file, if it was not specified in the command line
        # -----------------------------------------------------------------------------------------
        if pkcs12_pass == None:
            if sys.stdin.isatty():
                pkcs12_pass = input("Please enter the password for the PKCS12 file: ").strip()
                if len(pkcs12_pass) == 0:
                    print("WARNING: The password is empty, the PKCS12 file is not encrypted.")
            else:
                raise cc_ca.PasswordRequiredError("Please specify the password for the PKCS12 file as command line argument (--pkcs12-pass) or run the container in terminal mode, if you want to enter the password interactively.")

        # add the client
        # -----------------------------------------------------------------------------------------
        cert_serial, client_key, client_cert = ca.add_vpn_client(identity)

        # create a PKCS12 package containing the private key and the certificate
        # -----------------------------------------------------------------------------------------
        client_p12 = crypto.PKCS12Type()
        client_p12.set_ca_certificates([ca.cert])
        client_p12.set_privatekey(client_key)
        client_p12.set_certificate(client_cert)
        client_p12_data = client_p12.export(pkcs12_pass)

        # generate path of the PKCS12 archive, if the filename was not specified explicitly
        # -----------------------------------------------------------------------------------------
        if not pkcs12_path:
           pkcs12_path = os.path.join(OUTPUT_DIRECTORY, "{0} (CSN{1:010}).p12".format(identity, client_cert.get_serial_number()))
           pkcs12_path = os.path.normpath(pkcs12_path)

        # write PKCS12 archive
        # -----------------------------------------------------------------------------------------
        try:
            os.makedirs(os.path.dirname(pkcs12_path), exist_ok = True)
            with open(pkcs12_path, "wb+") as file:
                file.write(client_p12_data)
        except Exception as e:
            raise IoError("Writing PKCS12 file ({0}) failed.", pkcs12_path)

        # print info about the added client
        # -----------------------------------------------------------------------------------------
        if out_format.lower() == "text":
            self.__print_clients_text(ca.crl, [client_cert], [ "PKCS12 Archive" ], [ (os.path.relpath(pkcs12_path, OUTPUT_DIRECTORY), ) ])
        elif out_format.lower() == "tsv":
            self.__print_clients_tsv(ca.crl, [client_cert], [ "PKCS12 Archive" ], [ (os.path.relpath(pkcs12_path, OUTPUT_DIRECTORY), ) ])
        else:
            raise RuntimeError("Output format ({0}) is not supported.", out_format)

        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: list clients
    # -------------------------------------------------------------------------------------------------------------------------------------


    def list_clients(self, pos_args, named_args):
        """
        Prints all clients an their certificates (also expired and revoked certificates).

        Args:
            pos_args (tuple)  : Position encoded command line arguments:
                                0 (mandatory) => 'list'
                                1 (mandatory) => 'clients'
            named_args (dict) : Name encoded command line arguments:
                                'out-format' => Output type
                                                'text' => human readable text (default for terminal mode)
                                                'tsv'  => output optimized for scripting (TSV format, default for script mode)

        Returns:
            The application's exit code.

        """

        # evaluate positional command line arguments
        # -----------------------------------------------------------------------------------------
        if len(pos_args) != 2:
            raise CommandLineArgumentError("Expecting 2 positional arguments, you specified {0} ({1})", len(pos_args), pos_args)

        # perform common handler stuff
        # -----------------------------------------------------------------------------------------
        ca, out_format = self.__prepare_command_handler(pos_args, named_args)

        # print list
        # -----------------------------------------------------------------------------------------
        client_certs = ca.get_vpn_client_certificates(include_expired = True, include_revoked = True)
        sorted_client_certs = sorted(client_certs, key=lambda c: c.get_serial_number())                                    # sort by secondary criterion
        sorted_client_certs = sorted(sorted_client_certs, key=lambda c: self.__get_client_certificate_identity(c).lower()) # sort by primary criterion

        if out_format.lower() == "text":
            self.__print_clients_text(ca.crl, sorted_client_certs)
        elif out_format.lower() == "tsv":
            self.__print_clients_tsv(ca.crl, sorted_client_certs)
        else:
            raise RuntimeError("Output format ({0}) is not supported.", out_format)

        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: disable client
    # -------------------------------------------------------------------------------------------------------------------------------------

    
    def disable_client(self, pos_args, named_args):
        """
        Disables a client by revoking its client certificate(s)

        Args:
            pos_args (tuple)  : Position encoded command line arguments:
                                0 (mandatory) => 'disable'
                                1 (mandatory) => 'client'
                                2 (mandatory) => Identity of the client (e-mail address)
                                3 (optional)  => Serial number of the certificate to revoke (all active certificate are revoked, if not specified)
            named_args (dict) : Name encoded command line arguments:
                                'ca-pass'     => The password of the CA
                                'out-format'  => Output type
                                                 'text' => human readable text (default for terminal mode)
                                                 'tsv'  => output optimized for scripting (TSV format, default for script mode)

        Returns:
            The application's exit code.

        """

        # evaluate positional command line arguments
        # -----------------------------------------------------------------------------------------
        if len(pos_args) == 3:
            identity = pos_args[2]
            cert_serial = None
        elif len(pos_args) == 4:
            identity = pos_args[2]
            cert_serial = pos_args[3]
        else:   
            raise CommandLineArgumentError("Expecting 3 or 4 positional arguments, you specified {0} ({1})", len(pos_args), pos_args)

        # check format of the identity
        if not is_email_address(identity):
            raise CommandLineArgumentError("The specified identity ({0}) is not an e-mail address.", identity)

        # convert specified certificate serial number to an integer
        if cert_serial:
            try:
                cert_serial = int(cert_serial)
            except ValueError:
                raise CommandLineArgumentError("The specified certificate certial number ({0}) is invalid.", cert_serial)

        # perform common handler stuff
        # -----------------------------------------------------------------------------------------
        ca, out_format, = self.__prepare_command_handler(pos_args, named_args)

        # revoke certificate(s)
        # -----------------------------------------------------------------------------------------

        # get clients
        client_certs = ca.get_vpn_client_certificates(include_expired = False, include_revoked = False)

        # revoke certificate(s)
        revoked_certs = []
        for client_cert in client_certs:
            if cert_serial == None or cert_serial == client_cert.get_serial_number():
                ca.revoke_certificate(client_cert.get_serial_number(), "certificate_hold")
                revoked_certs.append(client_cert)

        # abort, if no certificate was revoked
        if len(revoked_certs) == 0:
            raise FileNotFoundError("The specified identity ({0}) has no active certificates.", identity)

        # re-read effected records
        revoked_certs = [ ca.get_certificate(x.get_serial_number()) for x in revoked_certs ] 

        # print effected certificates
        if out_format.lower() == "text":
            self.__print_clients_text(ca.crl, revoked_certs)
        elif out_format.lower() == "tsv":
            self.__print_clients_tsv(ca.crl, revoked_certs)
        else:
            raise RuntimeError("Output format ({0}) is not supported.", out_format)

        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: enable client
    # -------------------------------------------------------------------------------------------------------------------------------------

    
    def enable_client(self, pos_args, named_args):
        """
        Enables a previously disabled client by unrevoking its client certificate(s)

        Args:
            pos_args (tuple)  : Position encoded command line arguments:
                                0 (mandatory) => 'disable'
                                1 (mandatory) => 'client'
                                2 (mandatory) => Identity of the client (e-mail address)
                                3 (optional)  => Serial number of the certificate to unrevoke (all certificates that are not expired are unrevoked, if not specified)
            named_args (dict) : Name encoded command line arguments:
                                'ca-pass'     => The password of the CA
                                'out-format'  => Output type
                                                 'text' => human readable text (default for terminal mode)
                                                 'tsv'  => output optimized for scripting (TSV format, default for script mode)

        Returns:
            The application's exit code.

        """

        # evaluate positional command line arguments
        # -----------------------------------------------------------------------------------------
        if len(pos_args) == 3:
            identity = pos_args[2]
            cert_serial = None
        elif len(pos_args) == 4:
            identity = pos_args[2]
            cert_serial = pos_args[3]
        else:   
            raise CommandLineArgumentError("Expecting 3 or 4 positional arguments, you specified {0} ({1})", len(pos_args), pos_args)

        # check format of the identity
        if not is_email_address(identity):
            raise CommandLineArgumentError("The specified identity ({0}) is not an e-mail address.", identity)

        # convert specified certificate serial number to an integer
        if cert_serial:
            try:
                cert_serial = int(cert_serial)
            except ValueError:
                raise CommandLineArgumentError("The specified certificate certial number ({0}) is invalid.", cert_serial)

        # perform common handler stuff
        # -----------------------------------------------------------------------------------------
        ca, out_format, = self.__prepare_command_handler(pos_args, named_args)

        # unrevoke certificate(s)
        # -----------------------------------------------------------------------------------------

        # get clients
        client_certs = ca.get_vpn_client_certificates(include_expired = False, include_revoked = True)

        # unrevoke certificate(s)
        unrevoked_certs = []
        for client_cert in client_certs:
            if cert_serial == None or cert_serial == client_cert.get_serial_number():
                ca.unrevoke_certificate(client_cert.get_serial_number())
                unrevoked_certs.append(client_cert)

        # abort, if no certificate was unrevoked
        if len(unrevoked_certs) == 0:
            raise FileNotFoundError("The specified identity ({0}) does not have any revoked certificates that have not expired, yet.", identity)

        # re-read effected certificates
        unrevoked_certs = [ ca.get_certificate(x.get_serial_number()) for x in unrevoked_certs ] 

        # print effected certificates
        if out_format.lower() == "text":
            self.__print_clients_text(ca.crl, unrevoked_certs)
        elif out_format.lower() == "tsv":
            self.__print_clients_tsv(ca.crl, unrevoked_certs)
        else:
            raise RuntimeError("Output format ({0}) is not supported.", out_format)

        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: run / run-and-enter
    # -------------------------------------------------------------------------------------------------------------------------------------


    def run(self, pos_args, named_args):
        """
        Configures the container to run.

        Args:
            pos_args (tuple)  : Position encoded command line arguments:
                                0 (mandatory) => 'run' or 'run-and-enter'
            named_args (dict) : Name encoded command line arguments:
                                'ca-pass' => The password of the CA

        Returns:
            The application's exit code.

        """

        # evaluate positional command line arguments
        # -----------------------------------------------------------------------------------------
        if len(pos_args) != 1:
            raise CommandLineArgumentError("Expecting 1 positional argument, you specified {0} ({1})", len(pos_args), pos_args)


        # configure the services
        # -----------------------------------------------------------------------------------------
        self.__run_prepare(pos_args, named_args)
        self.__run_configure(pos_args, named_args)

        return EXIT_CODE_SUCCESS


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __run_prepare(self, pos_args, named_args):

        # ALLOW_INTERCLIENT_COMMUNICATION
        # -------------------------------------------------------------------------------------------------------------
        self.__allow_interclient_communication = get_env_setting_bool("ALLOW_INTERCLIENT_COMMUNICATION", False)

        # CLIENT_SUBNET_IPV4
        # -----------------------------------------------------------------------------------------
        self.__client_subnet_ipv4 = get_env_setting_string("CLIENT_SUBNET_IPV4", "10.0.0.0/24")
        try:
            self.__client_subnet_ipv4 = IPNetwork(self.__client_subnet_ipv4)
        except AddrFormatError:
            Log.write_error("The specified network ({0}) is not a valid IPv4 network.", self.__client_subnet_ipv4)
            raise

        # CLIENT_SUBNET_IPV6
        # (must be either in the Global Unicast Address (GUA) range or in the site-local range)
        # -------------------------------------------------------------------------------------------------------------

        # read environment variable
        self.__client_subnet_ipv6 = get_env_setting_string("CLIENT_SUBNET_IPV6", "fd00:DEAD:BEEF:AFFE::/64")
        try:
            self.__client_subnet_ipv6 = IPNetwork(self.__client_subnet_ipv6)
        except AddrFormatError:
            Log.write_error("The specified network ({0}) is not a valid IPv6 network.", self.__client_subnet_ipv6)
            raise

        # check whether the specified subnet belongs is in the GUA range or the ULA range
        if self.__client_subnet_ipv6.is_unicast() and not self.__client_subnet_ipv6.is_private():
            self.__client_subnet_ipv6_is_gua = True
            self.__client_subnet_ipv6_is_site_local = False
        elif self.__client_subnet_ipv6.is_private():
            self.__client_subnet_ipv6_is_gua = False
            self.__client_subnet_ipv6_is_site_local = True
        else:
            Log.write_error("The specified network ({0}) is neither in the GUA range ({1}) nor in the site-local range ({2}).",
                            str(self.__client_subnet_ipv6), str(IPV6_NETWORK_GUA), str(IPV6_NETWORK_SITE_LOCAL))
            raise RuntimeError()

        # USE_DOCKER_DNS
        # -------------------------------------------------------------------------------------------------------------
        self.__use_docker_dns = get_env_setting_bool("USE_DOCKER_DNS", True)

        # DNS_SERVERS
        # -------------------------------------------------------------------------------------------------------------
        if self.__use_docker_dns: self.__dns_servers = "127.0.0.11"
        else:                     self.__dns_servers = get_env_setting_string("DNS SERVERS", "8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844")
        self.__dns_servers = [ s.strip() for s in self.__dns_servers.split(",") ]

# TODO: add validation

        # VPN_HOSTNAMES
        # -------------------------------------------------------------------------------------------------------------
        self.__vpn_hostnames = get_env_setting_string("VPN_HOSTNAMES", socket.gethostname())
        self.__vpn_hostnames = [ s.strip() for s in self.__vpn_hostnames.split(",") ]

# TODO: add validation

        # PROTECT_CLIENTS_FROM_INTERNET
        # -------------------------------------------------------------------------------------------------------------
        self.__protect_clients_from_internet = get_env_setting_bool("PROTECT_CLIENTS_FROM_INTERNET", True)

        # determine IP addresses that map to the configured hostnames
        # -------------------------------------------------------------------------------------------------------------
        Log.write_info("Looking up IP addresses of the specified hostnames...")
        self.__ip_addresses_by_hostname = resolve_hostnames(self.__vpn_hostnames)
        for hostname,(ipv4_addresses,ipv6_addresses) in self.__ip_addresses_by_hostname.items():
            if len(ipv4_addresses) > 0:
                Log.write_info("- {0} : {1}".format(hostname, ",".join(ipv4_addresses)))
            if len(ipv6_addresses) > 0:
                Log.write_info("- {0} : {1}".format(hostname, ",".join(ipv6_addresses)))

        # setup cryptographic stuff
        # -------------------------------------------------------------------------------------------------------------
        self.__ca = cc_ca.CertificateAuthority()
        self.__init_pki_for_server(named_args)
        self.__init_pki_for_clients()

        # load af_key module is loaded (kernel support for IPSec)
        # -------------------------------------------------------------------------------------------------------------
        load_kernel_module("af_key")


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __run_configure(self, pos_args, named_args):

        # determine the start and the end of the client ip range
        # (the first address becomes the IP of the VPN server itself)
        # -------------------------------------------------------------------------------------------------------------

        # IPv4
        self.__own_ip_in_client_subnet_ipv4 = self.__client_subnet_ipv4[1]
        self.__client_ip_range_start_ipv4 = self.__client_subnet_ipv4[2]
        self.__client_ip_range_end_ipv4 = self.__client_subnet_ipv4[-1]

        # IPv6
        effective_client_subnet_ipv6 = self.__client_subnet_ipv6
        if self.__client_subnet_ipv6.prefixlen < 96:
          # subnet is too large, strongswan can only handle subnets up to /96 => use a smaller subnet
          effective_client_subnet_ipv6 = next(effective_client_subnet_ipv6.subnet(96))

        self.__own_ip_in_client_subnet_ipv6 = effective_client_subnet_ipv6[1]
        self.__client_ip_range_start_ipv6 = effective_client_subnet_ipv6[2]
        self.__client_ip_range_end_ipv6 = effective_client_subnet_ipv6[-1]

        # prepare context for the template engine that will generate strongswan.conf and ipsec.conf
        # -------------------------------------------------------------------------------------------------------------
        template_context = {
          "ca_cert_path"                   : self.__ca_cert_path,
          "ca_crl_path"                    : self.__ca_crl_path,
          "server_key_path"                : self.__server_key_path,
          "server_cert_path"               : self.__server_cert_path,
          "dns_servers"                    : self.__dns_servers,
          "ip_addresses_by_hostname"       : self.__ip_addresses_by_hostname,
          "client_subnet_ipv4"             : self.__client_subnet_ipv4,
          "client_subnet_ipv6"             : self.__client_subnet_ipv6,
          "own_ip_in_client_subnet_ipv4"   : self.__own_ip_in_client_subnet_ipv4,
          "client_ip_range_start_ipv4"     : self.__client_ip_range_start_ipv4,
          "client_ip_range_end_ipv4"       : self.__client_ip_range_end_ipv4,
          "own_ip_in_client_subnet_ipv6"   : self.__own_ip_in_client_subnet_ipv6,
          "client_ip_range_start_ipv6"     : self.__client_ip_range_start_ipv6,
          "client_ip_range_end_ipv6"       : self.__client_ip_range_end_ipv6,
        }

        # generate bind.conf.options
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = NAMED_CONF_OPTIONS_TEMPLATE_PATH).render(**template_context)
        with open(NAMED_CONF_OPTIONS_PATH, "wt") as f:
            f.write(rendered)

        # generate ipsec.conf
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = IPSEC_CONF_TEMPLATE_PATH).render(**template_context)
        with open(IPSEC_CONF_PATH, "wt") as f:
            f.write(rendered)

        # generate ipsec.secrets
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = IPSEC_SECRETS_TEMPLATE_PATH).render(**template_context)
        with open(IPSEC_SECRETS_PATH, "wt") as f:
            f.write(rendered)

        # generate strongswan.conf
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = STRONGSWAN_CONF_TEMPLATE_PATH).render(**template_context)
        with open(STRONGSWAN_CONF_PATH, "wt") as f:
            f.write(rendered)

        # generate ndppd.conf
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = NDPPD_CONF_TEMPLATE_PATH).render(**template_context)
        with open(NDPPD_CONF_PATH, "wt") as f:
            f.write(rendered)

        # disable ndppd, if VPN clients do not have global addresses (no need for neighbor discovery)
        # -------------------------------------------------------------------------------------------------------------
        if not self.__client_subnet_ipv6_is_gua:
            os.rename(SUPERVISORD_NDPPD_CONF_PATH, SUPERVISORD_NDPPD_CONF_PATH + ".inactive")

        # remount /proc/sys read-write to enable 'sysctl' to work properly
        # (only needed, if the container is not run in privileged mode)
        # -------------------------------------------------------------------------------------------------------------
        sys_proc_remounted_rw = False
        if does_mount_point_exist("/proc/sys") and is_mount_point_readonly("/proc/sys"):
            Log.write_info("Remounting /proc/sys read-write...")
            run(["mount", "-o", "remount,rw", "/proc/sys"], check=True, stdout=DEVNULL)
            sys_proc_remounted_rw = True

        # link the certificate and the CRL of the internal CA into /etc/ipsec.d/[cacerts|crls]
        # -------------------------------------------------------------------------------------------------------------
        os.symlink(self.__ca_crl_path, os.path.join("/etc/ipsec.d/crls", os.path.basename(self.__ca_crl_path)))
        os.symlink(self.__ca_cert_path, os.path.join("/etc/ipsec.d/cacerts", os.path.basename(self.__ca_cert_path)))

        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        # configure networking
        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        Log.write_info("Configuring networking...")

        # add a dummy device with an ip address for the vpn server in the client network
        run(["ip", "link", "add", "type", "dummy"], check=True, stdout=DEVNULL)
        run(["ip", "addr", "add", str(self.__own_ip_in_client_subnet_ipv4) + "/" + str(self.__client_subnet_ipv4.prefixlen), "dev", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "addr", "add", str(self.__own_ip_in_client_subnet_ipv6) + "/" + str(self.__client_subnet_ipv6.prefixlen), "dev", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "link", "set", "up", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "route", "add", str(self.__own_ip_in_client_subnet_ipv4), "dev", "dummy0"], check=True, stdout=DEVNULL)
        run(["ip", "route", "add", str(self.__own_ip_in_client_subnet_ipv6), "dev", "dummy0"], check=True, stdout=DEVNULL)

        # enable forwarding
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, stdout=DEVNULL)
        run(["sysctl", "-w", "net.ipv6.conf.default.forwarding=1"], check=True, stdout=DEVNULL)
        run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True, stdout=DEVNULL)

        # accept router advertisements on eth0, although we're forwarding packets
        run(["sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=2"], check=True, stdout=DEVNULL)

        # do not accept ICMP redirects (prevent MITM attacks)
        run(["sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0"], check=True, stdout=DEVNULL)
        run(["sysctl", "-w", "net.ipv6.conf.all.accept_redirects=0"], check=True, stdout=DEVNULL)

        # do not send ICMP redirects (we are not a router that should redirect others)
        # (in IPv6 redirects are mandatory for routers)
        run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], check=True, stdout=DEVNULL)

        # disable Path MTU discovery to prevent packet fragmentation problems
        run(["sysctl", "-w", "net.ipv4.ip_no_pmtu_disc=1"], check=True, stdout=DEVNULL)

        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        # configure firewalling
        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        Log.write_info("=> Configuring firewall")

        # filter all packets that have RH0 headers (deprecated, can be used for DoS attacks)
        # -------------------------------------------------------------------------------------------------------------
        ip6tables_add("INPUT",   "DROP", ["-m", "rt", "--rt-type", "0"], "RH0 Exploit Protection")
        ip6tables_add("FORWARD", "DROP", ["-m", "rt", "--rt-type", "0"], "RH0 Exploit Protection")
        ip6tables_add("OUTPUT",  "DROP", ["-m", "rt", "--rt-type", "0"], "RH0 Exploit Protection")

        # protect against spoofing attacks
        # -------------------------------------------------------------------------------------------------------------

        # prevent attacker from using the loopback address as source address
        iptables_add( "INPUT",   "DROP", ["!", "-i", "lo", "-s", "127.0.0.0/8"], "Anti-Spoofing")
        iptables_add( "FORWARD", "DROP", ["!", "-i", "lo", "-s", "127.0.0.0/8"], "Anti-Spoofing")
        ip6tables_add("INPUT",   "DROP", ["!", "-i", "lo", "-s", "::1/128"],     "Anti-Spoofing")
        ip6tables_add("FORWARD", "DROP", ["!", "-i", "lo", "-s", "::1/128"],     "Anti-Spoofing")

        # prevent attacker from using a VPN client address as source address
        iptables_add( "INPUT",   "DROP", ["-s", str(self.__client_subnet_ipv4), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")
        iptables_add( "FORWARD", "DROP", ["-s", str(self.__client_subnet_ipv4), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")
        ip6tables_add("INPUT",   "DROP", ["-s", str(self.__client_subnet_ipv6), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")
        ip6tables_add("FORWARD", "DROP", ["-s", str(self.__client_subnet_ipv6), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")

        # allow localhost to access everything
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT", "ACCEPT", ["-i", "lo"])
        ip6tables_add("INPUT", "ACCEPT", ["-i", "lo"])

        # allow IPSec related traffic
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT", "ACCEPT", ["-p", "udp", "--dport", "500"])
        iptables_add( "INPUT", "ACCEPT", ["-p", "udp", "--dport", "4500"])
        iptables_add( "INPUT", "ACCEPT", ["-p", "esp"])
        ip6tables_add("INPUT", "ACCEPT", ["-p", "udp", "--dport", "500"])
        ip6tables_add("INPUT", "ACCEPT", ["-p", "udp", "--dport", "4500"])
        ip6tables_add("INPUT", "ACCEPT", ["-p", "esp"])

        # allow packets that belong to already existing connections
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT",   "DROP",   ["-m", "conntrack", "--ctstate", "INVALID"])
        iptables_add( "INPUT",   "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
        iptables_add( "FORWARD", "DROP",   ["-m", "conntrack", "--ctstate", "INVALID"])
        iptables_add( "FORWARD", "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
        ip6tables_add("INPUT",   "DROP",   ["-m", "conntrack", "--ctstate", "INVALID"])
        ip6tables_add("INPUT",   "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
        ip6tables_add("FORWARD", "DROP",   ["-m", "conntrack", "--ctstate", "INVALID"])
        ip6tables_add("FORWARD", "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])

        # allow VPN clients to access the DNS server
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT", "ACCEPT", ["-p", "udp", "-s", str(self.__client_subnet_ipv4), "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec"])
        iptables_add( "INPUT", "ACCEPT", ["-p", "tcp", "-s", str(self.__client_subnet_ipv4), "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec"])
        ip6tables_add("INPUT", "ACCEPT", ["-p", "udp", "-s", str(self.__client_subnet_ipv6), "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec"])
        ip6tables_add("INPUT", "ACCEPT", ["-p", "tcp", "-s", str(self.__client_subnet_ipv6), "--dport", "53", "-m", "policy", "--dir", "in", "--pol", "ipsec"])

        # block packets between VPN clients (if requested)
        # -------------------------------------------------------------------------------------------------------------
        if not self.__allow_interclient_communication:
            iptables_add( "FORWARD", "DROP", ["-s", str(self.__client_subnet_ipv4), "-d", str(self.__client_subnet_ipv4)])
            ip6tables_add("FORWARD", "DROP", ["-s", str(self.__client_subnet_ipv6), "-d", str(self.__client_subnet_ipv6)])

        # allow ICMP packets
        # -------------------------------------------------------------------------------------------------------------

        # ICMP Type | INPUT | FORWARD | Description
        # -----------------------------------------------------------------------------------------
        #       0   |  yes  |   yes   | echo reply
        #       3   |  yes  |   yes   | destination unreachable
        #       8   |  yes  |   yes   | echo request (protect against ping-of-death)
        #      11   |  yes  |   yes   | time exceeded
        #      12   |  yes  |   yes   | parameter problem
        #      30   |  yes  |   yes   | traceroute
        # -----------------------------------------------------------------------------------------

        iptables_run(["-N", "AllowICMP_I"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "0"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "3"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "8", "-m", "limit", "--limit", "5/sec", "--limit-burst", "20"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "11"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "12"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "30"])
        iptables_add("AllowICMP_I", "DROP")
        iptables_add("INPUT", "AllowICMP_I", ["-p", "icmp"])

        iptables_run(["-N", "AllowICMP_F"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "0"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "3"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "8", "-m", "limit", "--limit", "5/sec", "--limit-burst", "20"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "11"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "12"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "30"])
        iptables_add("AllowICMP_F", "DROP")
        iptables_add("FORWARD", "AllowICMP_F", ["-p", "icmp"])

        #  ICMPv6 Type | INPUT | FORWARD | Description
        # -----------------------------------------------------------------------------------------
        #         1    |  yes  |   yes   | destination unreachable
        #         2    |  yes  |   yes   | packet too big
        #         3    |  yes  |   yes   | time exceeded
        #         4    |  yes  |   yes   | parameter problem
        #       128    |  yes  |   yes   | echo request (protect against ping-of-death)
        #       129    |  yes  |   yes   | echo reply
        #       130    |  yes  |   yes   | multicast listener query
        #       131    |  yes  |   yes   | version 1 multicast listener report
        #       132    |  yes  |   yes   | multicast listener done
        #       133    |  yes  |   no    | router solicitation
        #       134    |  yes  |   no    | router advertisement
        #       135    |  yes  |   no    | neighbor solicitation
        #       136    |  yes  |   no    | neighbor advertisement
        #       151    |  yes  |   no    | multicast router advertisement
        #       152    |  yes  |   no    | multicast router solicitation
        #       153    |  yes  |   no    | multicast router termination
        # -----------------------------------------------------------------------------------------
        ip6tables_run(["-N", "AllowICMP_I"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "1"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "2"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "3"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "4"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "128", "-m", "limit", "--limit", "5/sec", "--limit-burst", "10"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "129"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "130"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "131"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "132"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "133"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "134"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "135"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "136"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "151"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "152"])
        ip6tables_add("AllowICMP_I", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "153"])
        ip6tables_add("AllowICMP_I", "DROP")
        ip6tables_add("INPUT", "AllowICMP_I", ["-p", "icmpv6"])

        ip6tables_run(["-N", "AllowICMP_F"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "1"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "2"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "3"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "4"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "128", "-m", "limit", "--limit", "5/sec", "--limit-burst", "10"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "129"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "130"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "131"])
        ip6tables_add("AllowICMP_F", "ACCEPT", ["-p", "icmpv6", "--icmpv6-type", "132"])
        ip6tables_add("AllowICMP_F", "DROP")
        ip6tables_add("FORWARD", "AllowICMP_F", ["-p", "icmpv6"])

        # allow VPN clients to initiate new connections
        # -------------------------------------------------------------------------------------------------------------
        iptables_add("FORWARD", "ACCEPT", [
                     "-s", str(self.__client_subnet_ipv4),
                     "-m", "conntrack", "--ctstate", "NEW",
                     "-m", "policy", "--dir", "in", "--pol", "ipsec"])

        ip6tables_add("FORWARD", "ACCEPT", [
                      "-s", str(self.__client_subnet_ipv6),
                      "-m", "conntrack", "--ctstate", "NEW",
                      "-m", "policy", "--dir", "in", "--pol", "ipsec"])

        # allow packets that initiate new connections from the internet to VPN clients, if protection is disabled
        # -------------------------------------------------------------------------------------------------------------
        if not self.__protect_clients_from_internet:

            iptables_add("FORWARD", "ACCEPT", [
                         "-d", str(self.__client_subnet_ipv4),
                         "-m", "conntrack", "--ctstate", "NEW"])

            ip6tables_add("FORWARD", "ACCEPT", [
                          "-d", str(self.__client_subnet_ipv6),
                          "-m", "conntrack", "--ctstate", "NEW"])

        # drop everything else
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT",   "DROP")
        iptables_add( "FORWARD", "DROP")
        ip6tables_add("INPUT",   "DROP")
        ip6tables_add("FORWARD", "DROP")

        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        # Packet Mangling
        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        # Reduce the size of TCP packets by adjusting the packets' maximum segment size to prevent IP packet fragmentation
        # on some clients. This prevents issues with some VPN clients, but it is controversially discussed (google 'MSS
        # Clamping' for details). Many tunnel implementation use a tunnel MTU of 1400 bytes, so the following MSS values
        # should be reasonable:
        # - TCP MSS (IPv4): 1400 bytes (tunnel MTU) - 20 bytes (IPv4 header) - 20 bytes (TCP header) = 1360 bytes
        # - TCP MSS (IPv6): 1400 bytes (tunnel MTU) - 40 bytes (IPv6 header) - 20 bytes (TCP header) = 1340 bytes
        # -------------------------------------------------------------------------------------------------------------
        iptables_run([ "-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-s", str(self.__client_subnet_ipv4),
                       "-m", "policy", "--dir", "in", "--pol", "ipsec",
                       "-m", "tcpmss", "--mss", "1361:1500",
                       "-j", "TCPMSS", "--set-mss", "1360"])

        ip6tables_run(["-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-s", str(self.__client_subnet_ipv6),
                       "-m", "policy", "--dir", "in", "--pol", "ipsec",
                       "-m", "tcpmss", "--mss", "1341:1500",
                       "-j", "TCPMSS", "--set-mss", "1340"])

        # configure masquerading to allow clients to access the internet
        # -------------------------------------------------------------------------------------------------------------

        Log.write_info("=> Enabling masquerading for IPv4")

        iptables_add("POSTROUTING", "ACCEPT", [
                     "-t", "nat",
                     "-s", str(self.__client_subnet_ipv4),
                     "-m", "policy", "--dir", "out", "--pol", "ipsec"])

        iptables_add("POSTROUTING", "MASQUERADE", [
                     "-t", "nat",
                     "-s", str(self.__client_subnet_ipv4)])

        if self.__client_subnet_ipv6_is_site_local:

            # site local network (ip addresses are not valid on the internet)
            # => enable masquerading

            Log.write_info("=> Enabling masquerading for IPv6")

            ip6tables_add("POSTROUTING", "ACCEPT", [
                          "-t", "nat",
                          "-s", str(self.__client_subnet_ipv6),
                          "-m", "policy", "--dir", "out", "--pol", "ipsec"])

            ip6tables_add("POSTROUTING", "MASQUERADE", [
                          "-t", "nat",
                          "-s", str(self.__client_subnet_ipv6)])

        # remount /proc/sys read-only again
        # -------------------------------------------------------------------------------------------------------------
        if sys_proc_remounted_rw:
            Log.write_info("Remounting /proc/sys read-only...")
            run(["mount", "-o", "remount,ro", "/proc/sys"], check=True, stdout=DEVNULL)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __init_pki_for_server(self, named_args):
        """
        Initializes the Public Key Infrastructure (PKI) needed to run the VPN server.

        """

        external_server_key_exists = os.path.exists(EXTERNAL_PKI_SERVER_KEY_FILE)
        external_server_cert_exists = os.path.exists(EXTERNAL_PKI_SERVER_CERT_FILE)

        if external_server_key_exists and external_server_cert_exists:

            Log.write_note("Found external server key and certificate to use for server authentication.")

            self._server_key_path  = EXTERNAL_PKI_SERVER_KEY_FILE
            self._server_cert_path = EXTERNAL_PKI_SERVER_CERT_FILE

        else:

            Log.write_note("External server key and/or certificate was not found. Using the internal PKI for server authentication.")
            Log.write_note("Please ensure, that the certificate of the internal CA is installed at your clients!")

            # subject alternative names expected to be in the certificate
            sans = [ "DNS:" + s for s in self.__vpn_hostnames ]

            create_server_cert = True
            if os.path.exists(INTERNAL_PKI_SERVER_KEY_FILE) and os.path.exists(INTERNAL_PKI_SERVER_CERT_FILE):

                # a key file and a certificate file exists
                # => there is a good chance, we can use them...
                create_server_cert = False

                # read server key
                with open(INTERNAL_PKI_SERVER_KEY_FILE, "rb") as f:
                    server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

                # read server certificate
                with open(INTERNAL_PKI_SERVER_CERT_FILE, "rb") as f:
                    server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

                if server_cert.get_issuer() != self.__ca.cert.get_subject():
                    Log.write_note("The server certificate was not issued by the internal CA. The certificate must be regenerated.")
                    create_server_cert = True

                # check whether the server certificate has expired
                if not create_server_cert:
                    if server_cert.has_expired():
                        Log.write_note("The server certificate has expired. The certificate must be regenerated.")
                        create_server_cert = True

                # check CN in certificate
                if not create_server_cert:
                    cert_hostname = server_cert.get_subject().CN
                    expected_hostname = ":".join(sans[0].split(":")[1:])
                    if cert_hostname != expected_hostname:
                        Log.write_warning("The server certificate was made for '{0}', but '{1}' is currently configured. The certficate must be regenerated.", cert_hostname, expected_hostname)
                        create_server_cert = True

                # check subjectAltName extension
                if not create_server_cert:
                    foundSubjectAltNameExtension = False
                    for cert_extension_index in range(0, server_cert.get_extension_count()):
                        extension = server_cert.get_extension(cert_extension_index)
                        if extension.get_short_name() == b'subjectAltName':
                            cert_subjects = str(extension)
                            expected_subjects = ", ".join(sans)
                            if cert_subjects != expected_subjects:
                                Log.write_warning("Found extension 'subjectAltName', but it is '{0}', should be '{1}'.", cert_subjects, expected_subjects)
                                create_server_cert = True
                            foundSubjectAltNameExtension = True
                            break
                    if not foundSubjectAltNameExtension:
                        Log.write_note("The server certificate does not contain a 'subjectAltName' extension. The certificate must be regenerated.", server_cert_path)
                        create_server_cert = True

            # (re-)generate server credentials, if necessary
            if create_server_cert:

                # creating a new certficate requires the private key of the CA
                ca_pass = None
                if len(named_args["ca-pass"]) > 0: ca_pass = named_args[0]
                if ca_pass == None:
                    if sys.stdin.isatty():
                        ca_pass = input("Please enter the password of the CA: ").strip()
                    else:
                        raise cc_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")
                self.__ca.password = ca_pass

                # create new key and certificate for the VPN server
                server_key, server_cert = self.__ca.create_vpn_server_certificate(sans, server_key = None)

                # write key file
                with open(INTERNAL_PKI_SERVER_KEY_FILE, "wb+") as f:
                    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))
                os.chown(INTERNAL_PKI_SERVER_KEY_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_KEY_FILE, S_IRUSR | S_IWUSR)

                # write certificate file
                with open(INTERNAL_PKI_SERVER_CERT_FILE, "wb+") as f:
                    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
                os.chown(INTERNAL_PKI_SERVER_CERT_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_CERT_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            else:

                Log.write_info("The stored server certificate is valid and can be used as is.")


            self.__server_key_path  = INTERNAL_PKI_SERVER_KEY_FILE
            self.__server_cert_path = INTERNAL_PKI_SERVER_CERT_FILE

        # log the certificate of the VPN server
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, server_cert).decode('utf-8')
        Log.write_info("Certificate of the VPN server\n{1}\n{0}\n{1}", dump, SEPARATOR_LINE)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __init_pki_for_clients(self):
        """
        """

        external_server_ca_cert_exists = os.path.exists(EXTERNAL_PKI_CA_CERT_FILE)

        if external_server_ca_cert_exists:

            Log.write_note("Found external CA certificate to use for client authentication.")

            self.__ca_cert_path = EXTERNAL_PKI_CA_CERT_FILE
            self.__ca_crl_path  = None  # get from environment

        else:

            Log.write_note("External CA certificate was not found. Using the internal PKI for client authentication.")

            self.__ca_cert_path  = self.__ca.cert_path
            self.__ca_crl_path   = self.__ca.crl_path



    # -------------------------------------------------------------------------------------------------------------------------------------
    # Helper functions
    # -------------------------------------------------------------------------------------------------------------------------------------

    def __handle_exceptions(self, error):
        """
        Is called when a registered exception is thrown out of a command line handler and converts the exception into an exit code
        that is returned from the startup system.

        Args:
            error (Error) : Exception to handle.

        Returns:
            Exit code to return from the startup system.

        """
        if type(error) is cc_ca.NotInitializedError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_CA_NOT_INITIALIZED
        elif type(error) is cc_ca.AlreadyInitializedError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_CA_ALREADY_INITIALIZED
        elif type(error) is cc_ca.PasswordRequiredError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_PASSWORD_REQUIRED 
        elif type(error) is cc_ca.InvalidPasswordError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_PASSWORD_WRONG
        elif type(error) is cc_ca.InconsistencyDetectedError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_CA_INCONSISTENCY_DETECTED
        else:
            raise GeneralError("An unexpected error occurred.\n{0}", error)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __get_client_certificate_identity(self, client_cert):
        """
        Gets the identity of a client out of its client certificate.

        Args:
            client_cert (OpenSSL X509 object) : The client certificate

        """

        subject = client_cert.get_subject().get_components()
        subject = ",".join(["{0}={1}".format(key.decode("utf-8"), value.decode("utf-8")) for key, value in subject])
        identity = subject.split(",")[-1].lstrip("CN=")

        return identity


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __print_clients_text(self, crl, client_certs, additional_field_names = [], additional_field_values = []):
        """
        Prints the specified client certificates in human-readable text.

        Args:
            crl (OpenSSL CRL object)                        : The CRL of the CA
            client_certs (list of OpenSSL X509 objects)     : Client certificates to print
            additional_field_names (list of str)            : Names of additional fields to append
            additional_fields_values (list of tuple of str) : Values of additional fields to append (one tuple per certificate)

        """

        # prepare data to collect 
        field_names = [ "Identity", "Serial", "Not Before", "Not After", "Revoked", *additional_field_names ]
        field_widths = [ len(name) for name in field_names ]
        field_values = []

        # get the list of revocations out of the CRL
        revoked = crl.get_revoked()

        for index, client_cert in enumerate(client_certs):

            # get the identity the client certificate is associated with (str)
            identity = self.__get_client_certificate_identity(client_cert)

            # get start of validity period (datetime)
            notBefore = datetime.strptime(client_cert.get_notBefore().decode("ascii"), ASN1_DATETIME_FORMAT)

            # get end of validity period (datetime)
            notAfter = datetime.strptime(client_cert.get_notAfter().decode("ascii"), ASN1_DATETIME_FORMAT)

            # get revocation date (datetime or None)
            revocation_date = None
            if revoked:
                for revoke in revoked:
                    if client_cert.get_serial_number() == int(revoke.get_serial(), 16):
                        revocation_date = datetime.strptime(revoke.get_rev_date().decode("ascii"), ASN1_DATETIME_FORMAT)
                        break

            # format data and store record
            record = [identity,
                      "{0:010}".format(client_cert.get_serial_number()),
                      notBefore.strftime(TEXT_OUTPUT_DATETIME_FORMAT),
                      notAfter.strftime(TEXT_OUTPUT_DATETIME_FORMAT),
                      revocation_date.strftime(TEXT_OUTPUT_DATETIME_FORMAT) if revocation_date else ""]

            # append additional fields, if specified
            if index < len(additional_field_values):
                additional_data = additional_field_values[index]
                if len(additional_data) < len(additional_field_names):
                    record.extend(additional_data)
                    record.extend([""] * len(additional_field_names) - len(additional_data))
                elif len(additional_data) > len(additional_field_names):
                    record.extend(additional_data[0:len(additional_field_names)])
                else:
                    record.extend(additional_data)
            else:
                record.extend([""] * len(additional_field_names))

            field_values.append(record)

            # update the maximum field width
            for i in range(len(field_names)):
                field_widths[i] = max(field_widths[i], len(record[i]))

        # print the header
        line = "|"
        for index, field_name in enumerate(field_names):
            line_format = " {{0: <{0}}} |".format(field_widths[index])
            line += line_format.format(field_name)
        print(line)

        # print header line
        line = "|"
        for index, field_name in enumerate(field_names):
            line += "-" * (field_widths[index] + 2)
            if index + 1 < len(field_names): line += "+"
            else:                            line += "|"
        print(line)
        
        # print the records
        for record in field_values:
            line = "|"
            for index, field_value in enumerate(record):
                line_format = " {{0: <{0}}} |".format(field_widths[index])
                line += line_format.format(field_value)
            print(line)

        # print bottom line
        line = "|"
        for index, field_name in enumerate(field_names):
            line += "-" * (field_widths[index] + 2)
            if index + 1 < len(field_names): line += "+"
            else:                            line += "|"
        print(line)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __print_clients_tsv(self, crl, client_certs, additional_field_names = [], additional_field_values = []):
        """
        Prints the specified client certificates in human-readable text.

        Args:
            crl (OpenSSL CRL object)                        : The CRL of the CA
            client_certs (list of OpenSSL X509 objects)     : Client certificates to print
            additional_field_names (list of str)            : Names of additional fields to append
            additional_fields_values (list of tuple of str) : Values of additional fields to append (one tuple per certificate)

        """

        # print header
        line = "Identity"
        line += "\tSerial"
        line += "\tNot Before"
        line += "\tNot After"
        line += "\tRevoked"
        for field_name in additional_field_names:
            line += "\t" + field_name
        print(line)

        # get the list of revocations out of the CRL
        revoked = crl.get_revoked()

        # print certificates (one line per certificate)
        for index, client_cert in enumerate(client_certs):

            # get the identity the client certificate is associated with (str)
            identity = self.__get_client_certificate_identity(client_cert)

            # get start of validity period (datetime)
            notBefore = datetime.strptime(client_cert.get_notBefore().decode("ascii"), ASN1_DATETIME_FORMAT)

            # get end of validity period (datetime)
            notAfter = datetime.strptime(client_cert.get_notAfter().decode("ascii"), ASN1_DATETIME_FORMAT)

            # get revocation date (datetime or None)
            revocation_date = None
            if revoked:
                for revoke in revoked:
                    if client_cert.get_serial_number() == int(revoke.get_serial(), 16):
                        revocation_date = datetime.strptime(revoke.get_rev_date().decode("ascii"), ASN1_DATETIME_FORMAT)
                        break

            # format data and store record
            record = [identity,
                      str(client_cert.get_serial_number()),
                      notBefore.isoformat(),
                      notAfter.isoformat(),
                      revocation_date.isoformat() if revocation_date else ""]

            # append additional fields
            if index < len(additional_field_values):
                additional_data = additional_field_values[index]
                if len(additional_data) < len(additional_field_names):
                    record.extend(additional_data)
                    record.extend([""] * len(additional_field_names) - len(additional_data))
                elif len(additional_data) > len(additional_field_names):
                    record.extend(additional_data[0:len(additional_field_names)])
                else:
                    record.extend(additional_data)
            else:
                record.extend([""] * len(additional_field_names))

            # print the record
            line = record[0]
            for field_value in record[1:]:
                line += "\t" + field_value
            print(line)                


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __prepare_command_handler(self, pos_args, named_args):
        """
        Performs common steps when processing a command.

        Args:
            pos_args (tuple)  : Positional command line arguments:
            named_args (dict) : Name encoded command line arguments:
                                'ca-pass'     => The password of the CA
                                'out-format'  => Output type
                                                 'text' => human readable text (default for terminal mode)
                                                 'tsv'  => output optimized for scripting (TSV format, default for script mode)

        Returns:
            A tuple containing the following data:
            - The internal certificate authority (obj)
            - The output format

        """

        # evaluate named command line arguments
        # -----------------------------------------------------------------------------------------
        command_requires_ca_pass = "ca-pass" in named_args
        ca_pass                  = named_args["ca-pass"][0]    if "ca-pass" in named_args and len(named_args["ca-pass"]) > 0 else None
        out_format               = named_args["out-format"][0] if "out-format" in named_args and len(named_args["out-format"]) > 0 else None

        if not out_format:
            if sys.stdin.isatty(): out_format = "text"   # terminal mode
            else:                  out_format = "tsv"    # script mode
         
        if not out_format.lower() in [ "text", "tsv" ]:
            raise CommandLineArgumentError("Output format ({0}) is not supported.", out_format)

        # ensure the CA password is set properly, if necessary
        # -----------------------------------------------------------------------------------------
        ca = cc_ca.CertificateAuthority()
        if command_requires_ca_pass:

            if ca.password_required:

                # query user to enter the CA password, if it was not specified in the command line
                if ca_pass == None:
                    if sys.stdin.isatty():
                        ca_pass = input("Please enter the password of the CA: ").strip()
                    else:
                        raise cc_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")

                # set the CA password
                ca.password = ca_pass  # can raise cc_ca.InvalidPasswordError

        # CA is set up properly, command can be handled
        # -----------------------------------------------------------------------------------------
        return (ca, out_format)
