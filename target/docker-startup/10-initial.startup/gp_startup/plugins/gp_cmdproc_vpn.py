"""
This module contains the command processing plugin handling VPN related commands.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
import shutil
import socket
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from getpass import getpass
from OpenSSL import crypto
from mako.template import Template
from netaddr import IPAddress, IPNetwork, AddrFormatError
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from subprocess import run, DEVNULL

from ..gp_log import Log
from ..gp_cmdproc import CommandProcessor, PositionalArgument, NamedArgument
from ..gp_errors import ExitCodeError, FileNotFoundError, GeneralError, CommandLineArgumentError, IoError, EXIT_CODE_SUCCESS
from ..gp_helpers import read_text_file, write_text_file, print_error, readline_if_no_tty, \
                         get_env_setting_bool, get_env_setting_integer, get_env_setting_string, \
                         iptables_run, iptables_add, ip6tables_run, ip6tables_add, \
                         does_mount_point_exist, is_mount_point_readonly, \
                         load_kernel_module, resolve_hostnames, \
                         is_email_address
from . import gp_ca


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
SWANCTL_CONF_PATH                = "/etc/swanctl/swanctl.conf"
SWANCTL_CONF_TEMPLATE_PATH       = "/etc/swanctl/swanctl.conf.mako"
STRONGSWAN_CONF_PATH             = "/etc/strongswan.conf"
STRONGSWAN_CONF_TEMPLATE_PATH    = "/etc/strongswan.conf.mako"
NAMED_CONF_OPTIONS_PATH          = "/etc/bind/named.conf.options"
NAMED_CONF_OPTIONS_TEMPLATE_PATH = "/etc/bind/named.conf.options.mako"

# path of the data output directory
OUTPUT_DIRECTORY = "/data-out"

# paths of keys/certificates, when an external CA is used
EXTERNAL_PKI_BASE_DIR             = "/external-ca"
EXTERNAL_PKI_CLIENT_CA_CERT_FILE  = os.path.join(EXTERNAL_PKI_BASE_DIR, "client-ca.crt")
EXTERNAL_PKI_SERVER_CERT_FILE     = os.path.join(EXTERNAL_PKI_BASE_DIR, "server.crt")
EXTERNAL_PKI_SERVER_KEY_FILE      = os.path.join(EXTERNAL_PKI_BASE_DIR, "server.key")

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
                                              NamedArgument("ca-pass", min_occurrence = 0, max_occurrence = 1, from_stdin=True))

        self.add_handler(self.run,            PositionalArgument("run-and-enter"),
                                              NamedArgument("ca-pass", min_occurrence = 0, max_occurrence = 1, from_stdin=True))

        self.add_handler(self.init,           PositionalArgument("init"),
                                              NamedArgument("ca-pass",             min_occurrence = 0, max_occurrence = 1, from_stdin=True),
                                              NamedArgument("ca-key-type",         min_occurrence = 1, max_occurrence = 1),
                                              NamedArgument("server-key-type",     min_occurrence = 1, max_occurrence = 1),
                                              NamedArgument("client-key-type",     min_occurrence = 1, max_occurrence = 1),
                                              NamedArgument("ca-cert-subject",     min_occurrence = 1, max_occurrence = 1),
                                              NamedArgument("server-cert-subject", min_occurrence = 1, max_occurrence = 1),
                                              NamedArgument("client-cert-subject", min_occurrence = 1, max_occurrence = 1))

        self.add_handler(self.add_client,     PositionalArgument("add"),
                                              PositionalArgument("client"),
                                              NamedArgument("ca-pass",     min_occurrence = 0, max_occurrence = 1, from_stdin=True),
                                              NamedArgument("out-format",  min_occurrence = 0, max_occurrence = 1),
                                              NamedArgument("pkcs12-pass", min_occurrence = 0, max_occurrence = 1, from_stdin=True),
                                              NamedArgument("pkcs12-file", min_occurrence = 0, max_occurrence = 1))

        self.add_handler(self.list_clients,   PositionalArgument("list"),
                                              PositionalArgument("clients"),
                                              NamedArgument("out-format", min_occurrence = 0, max_occurrence = 1))

        self.add_handler(self.disable_client, PositionalArgument("disable"),
                                              PositionalArgument("client"),
                                              NamedArgument("ca-pass", min_occurrence = 0, max_occurrence = 1, from_stdin=True),
                                              NamedArgument("out-format", min_occurrence = 0, max_occurrence = 1))

        self.add_handler(self.enable_client,  PositionalArgument("enable"),
                                              PositionalArgument("client"),
                                              NamedArgument("ca-pass", min_occurrence = 0, max_occurrence = 1, from_stdin=True),
                                              NamedArgument("out-format", min_occurrence = 0, max_occurrence = 1))

        # register exception handlers for exceptions raised by the internal CA
        self.add_exception_handler(self.__handle_exceptions, gp_ca.NotInitializedError)
        self.add_exception_handler(self.__handle_exceptions, gp_ca.AlreadyInitializedError)
        self.add_exception_handler(self.__handle_exceptions, gp_ca.PasswordRequiredError)
        self.add_exception_handler(self.__handle_exceptions, gp_ca.InvalidPasswordError)
        self.add_exception_handler(self.__handle_exceptions, gp_ca.InconsistencyDetectedError)


    # -------------------------------------------------------------------------------------------------------------------------------------
    # Command Handler: init
    # -------------------------------------------------------------------------------------------------------------------------------------


    def init(self, pos_args, named_args):
        """
        Initializes the internal CA environment.

        If the container was run with the flags --interactive and --tty, the handler operates in interactive mode, i.e. the
        user is queried, if some information is missing. The output in this mode is made for humans.

        If the container was run with the flag --interactive, but without --tty, the handler operates in script mode, i.e.
        any data needed for the operation must be specified using command line parameters or piped in via stdin. Input to
        stdin is expected to contain one line: the password of the CA. Although using stdin is a bit more lengthy, it minimizes
        the chance of leaking credentials as passwords are neither visible in the process list nor via the inspection features
        of the docker engine API.


        Args:
            pos_args (tuple)  : Positional command line arguments
                                0 (mandatory) => 'init'
            named_args (dict) : Named command line arguments
                                'ca-pass'                         => Password to protect CA related data with (empty to disable protection)
                                'ca-key-type'         (mandatory) => Private key type the Ca will use.
                                'server-key-type'     (mandatory) => Private key type the server will use.
                                'client-key-type'     (mandatory) => Private key type clients will use.
                                                                     Must be one of the following:
                                                                     - 'rsa2048'   : RSA, 2048 bit
                                                                     - 'rsa3072'   : RSA, 3072 bit
                                                                     - 'rsa4096'   : RSA, 4096 bit
                                                                     - 'secp256r1' : ECC, NIST/SECG curve over a 256 bit prime field
                                                                     - 'secp384r1' : ECC, NIST/SECG curve over a 384 bit prime field
                                                                     - 'secp521r1' : ECC, NIST/SECG curve over a 521 bit prime field
                                'ca-cert-subject'     (mandatory) => Subject name of the CA certificate (Distinguished name, DN)
                                'server-cert-subject' (mandatory) => Subject name of generated server certificate (Distinguished name, DN)
                                                                     The value of the 'CN' attribute is overwritten with the server's hostname.
                                'client-cert-subject' (mandatory) => Subject name of generated client certificate (Distinguished name, DN)
                                                                     The value of the 'CN' attribute is overwritten with the client's identity.

        Returns:
            The application's exit code.

        """

        # check positional command line arguments
        if len(pos_args) != 1:
            raise CommandLineArgumentError("Expecting 1 positional argument only, you specified {0} ({1})", len(pos_args), pos_args)

        # evaluate named command line arguments
        ca_pass             = named_args["ca-pass" ][0]            if len(named_args["ca-pass"])  > 0            else None
        ca_key_type         = named_args["ca-key-type"][0]         if len(named_args["ca-key-type"]) > 0         else None
        server_key_type     = named_args["server-key-type"][0]     if len(named_args["server-key-type"]) > 0     else None
        client_key_type     = named_args["client-key-type"][0]     if len(named_args["client-key-type"]) > 0     else None
        ca_cert_subject     = named_args["ca-cert-subject"][0]     if len(named_args["ca-cert-subject"]) > 0     else None
        server_cert_subject = named_args["server-cert-subject"][0] if len(named_args["server-cert-subject"]) > 0 else None
        client_cert_subject = named_args["client-cert-subject"][0] if len(named_args["client-cert-subject"]) > 0 else None

        # validate the 'ca-key-type' argument
        if ca_key_type == None or not ca_key_type.lower() in [kt.name for kt in gp_ca.KeyTypes.all()]:
            error = "Please specify a supported key type to use for the CA. You may specfify:\n"
            max_length = max([len(x.name) for x in gp_ca.KeyTypes.all()])
            line_format = "--ca-key-type={{0:{0}}}   {{1}}\n".format(max_length)
            for type in gp_ca.KeyTypes.all():
                error += line_format.format(type.name, type.description)
            raise CommandLineArgumentError(error)

        # validate the 'server-key-type' argument
        if server_key_type == None or not server_key_type.lower() in [kt.name for kt in gp_ca.KeyTypes.all()]:
            error = "Please specify a supported key type to use for the VPN server. You may specfify:\n"
            max_length = max([len(x.name) for x in gp_ca.KeyTypes.all()])
            line_format = "--server-key-type={{0:{0}}}   {{1}}\n".format(max_length)
            for type in gp_ca.KeyTypes.all():
                error += line_format.format(type.name, type.description)
            raise CommandLineArgumentError(error)

        # validate the 'client-key-type' argument
        if client_key_type == None or not client_key_type.lower() in [kt.name for kt in gp_ca.KeyTypes.all()]:
            error = "Please specify a supported key type to use for VPN clients. You may specfify:\n"
            max_length = max([len(x.name) for x in gp_ca.KeyTypes.all()])
            line_format = "--client-key-type={{0:{0}}}   {{1}}\n".format(max_length)
            for type in gp_ca.KeyTypes.all():
                error += line_format.format(type.name, type.description)
            raise CommandLineArgumentError(error)

        # validate the arguments 'ca-cert-subject', 'server-cert-subject' and 'client-cert-subject'
        try:     gp_ca.CertificateAuthority.build_x509_name(ca_cert_subject)
        except:  raise CommandLineArgumentError("Invalid DN ({0}).", ca_cert_subject)
        try:     gp_ca.CertificateAuthority.build_x509_name(server_cert_subject)
        except:  raise CommandLineArgumentError("Invalid DN ({0}).", server_cert_subject)
        try:     gp_ca.CertificateAuthority.build_x509_name(client_cert_subject)
        except:  raise CommandLineArgumentError("Invalid DN ({0}).", client_cert_subject)

        # check whether the CA environment is already initialized
        ca = gp_ca.CertificateAuthority()
        if ca.is_inited():
            raise gp_ca.AlreadyInitializedError("The internal CA is already initialized.")

        # query user to enter the password, if it was not specified in the command line
        if ca_pass == None:
            if sys.stdin.isatty():
                ca_pass = getpass("Please enter the password to protect the CA with: ").strip()
                if len(ca_pass) > 0:
                    ca_pass_verify = getpass("Please enter the password once again: ").strip()
                    if ca_pass != ca_pass_verify:
                        raise gp_ca.InvalidPasswordError("Password verification failed.")
                else:
                    print("The password is empty. CA related data is not encrypted!")
            else:
                raise gp_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")

        # initialize the CA environment
        ca.init(ca_pass, ca_key_type, server_key_type, client_key_type, ca_cert_subject, server_cert_subject, client_cert_subject)

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
                pkcs12_pass = getpass("Please enter the password for the PKCS12 file: ").strip()
                if len(pkcs12_pass) > 0:
                    pkcs12_pass_verify = getpass("Please enter the password once again: ").strip()
                    if pkcs12_pass != pkcs12_pass_verify:
                        raise gp_ca.InvalidPasswordError("Password verification failed.")
                else:
                    print("WARNING: The password is empty, the PKCS12 file is not encrypted.")
            else:
                raise gp_ca.PasswordRequiredError("Please specify the password for the PKCS12 file as command line argument (--pkcs12-pass) or run the container in terminal mode, if you want to enter the password interactively.")

        # add the client
        # -----------------------------------------------------------------------------------------
        cert_serial, client_key, client_cert = ca.add_vpn_client(identity)

        # create a PKCS12 package containing the private key and the certificate
        # -----------------------------------------------------------------------------------------
        try:
            # OpenSSL changed the attribute name since 17.1.0 (see #10)
            client_p12 = crypto.PKCS12()
        except AttributeError:
            client_p12 = crypto.PKCS12Type()
        client_p12.set_ca_certificates([ crypto.X509.from_cryptography(ca.cert) ])
        client_p12.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, client_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())))
        client_p12.set_certificate(crypto.X509.from_cryptography(client_cert))
        client_p12_data = client_p12.export(pkcs12_pass)

        # generate path of the PKCS12 archive, if the filename was not specified explicitly
        # -----------------------------------------------------------------------------------------
        if not pkcs12_path:
           pkcs12_path = os.path.join(OUTPUT_DIRECTORY, "{0} (CSN{1:010}).p12".format(identity, client_cert.serial_number))
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
        sorted_client_certs = sorted(client_certs, key=lambda c: c.serial_number)                                          # sort by secondary criterion
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
                raise CommandLineArgumentError("The specified certificate serial number ({0}) is invalid.", cert_serial)

        # perform common handler stuff
        # -----------------------------------------------------------------------------------------
        ca, out_format, = self.__prepare_command_handler(pos_args, named_args)

        # revoke certificate(s)
        # -----------------------------------------------------------------------------------------

        # get clients
        client_certs = ca.get_vpn_client_certificates(identity = identity, include_expired = False, include_revoked = False)

        # revoke certificate(s)
        revoked_certs = []
        for client_cert in client_certs:
            if cert_serial == None or cert_serial == client_cert.serial_number:
                ca.revoke_certificate(client_cert.serial_number, "certificate_hold")
                revoked_certs.append(client_cert)

        # abort, if no certificate was revoked
        if len(revoked_certs) == 0:
            if cert_serial: raise FileNotFoundError("The specified identity ({0}) does not have an active certificate with the specified serial number ({1}).", identity, cert_serial)
            else:           raise FileNotFoundError("The specified identity ({0}) does not have any active certificates.", identity)

        # re-read effected records
        revoked_certs = [ ca.get_certificate(x.serial_number) for x in revoked_certs ]

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
                                0 (mandatory) => 'enable'
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
        client_certs = ca.get_vpn_client_certificates(identity = identity, include_expired = False, include_revoked = True)

        # unrevoke certificate(s)
        unrevoked_certs = []
        for client_cert in client_certs:
            if cert_serial == None or cert_serial == client_cert.serial_number:
                ca.unrevoke_certificate(client_cert.serial_number)
                unrevoked_certs.append(client_cert)

        # abort, if no certificate was unrevoked
        if len(unrevoked_certs) == 0:
            if cert_serial: raise FileNotFoundError("The specified identity ({0}) does not have a revoked certificates with the specified serial number ({1}).", identity, cert_serial)
            else:           raise FileNotFoundError("The specified identity ({0}) does not have any revoked certificates.", identity)

        # re-read effected certificates
        unrevoked_certs = [ ca.get_certificate(x.serial_number) for x in unrevoked_certs ]

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

        # USE_INTERFACES
        # -------------------------------------------------------------------------------------------------------------
        interfaces = get_env_setting_string("USE_INTERFACES", "eth0")
        self.__interfaces = []
        for interface in [ x.strip() for x in interfaces.split(",") ]:
            if interface.lower() == "all":
                self.__interfaces = []  # strongswan uses all interfaces, if no interface is specified
                break
            if len(interface) > 0:
                self.__interfaces.append(interface)

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
        self.__client_subnet_ipv6 = get_env_setting_string("CLIENT_SUBNET_IPV6", "fd00:dead:beef:affe::/64")
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

        # TCP_MSS
        # -------------------------------------------------------------------------------------------------------------
        self.__tcp_mss = get_env_setting_integer("TCP_MSS", 1200)

        # IKE_PROPOSALS
        # -------------------------------------------------------------------------------------------------------------

        # IKE - Proposal 1: AEAD (encryption + integrity combined) + PRF + DH Group (for Perfect Forward Secrecy)
        # - encryption/integrity: aes[128|256][ccm|gcm][8|12|16]
        # - PRF: prfmd5, prfsha1, prfaesxcbc, prfaescmac, prfsha[256|384|512]
        # - DH Groups: Regular Groups: modp[2048|3072|4096|6144|8192]
        #              NIST Elliptic Curve Groups: ecp[192|224|256|384|521]
        #              Brainpool Curve Groups: ecp[224|256|384|512]bp
        #              Elliptic Curve 25519
        default_ike_proposals  = "aes128gcm8-aes128gcm12-aes128gcm16-aes256gcm8-aes256gcm12-aes256gcm16-aes128ccm8-aes128ccm12-aes128ccm16-aes256ccm8-aes256ccm12-aes256ccm16-"
        default_ike_proposals += "prfmd5-prfsha1-prfaesxcbc-prfaescmac-prfsha256-prfsha384-prfsha512-"
        default_ike_proposals += "modp2048-modp3072-modp4096-modp6144-modp8192-ecp192-ecp224-ecp256-ecp384-ecp521-ecp224bp-ecp256bp-ecp384bp-ecp512bp-curve25519,"

        # IKE - Proposal 2: Encryption + Integrity + PRF + DH Group (for Perfect Forward Secrecy)
        # - Encryption: aes[128|256]
        # - Integrity: md5, sha1, aesxcbc, aescmac, sha[256|384|512]
        # - PRF: prfmd5, prfsha1, prfaesxcbc, prfaescmac, prfsha[256|384|512]
        # - DH Groups: Regular Groups: modp[2048|3072|4096|6144|8192]
        #              NIST Elliptic Curve Groups: ecp[192|224|256|384|521]
        #              Brainpool Curve Groups: ecp[224|256|384|512]bp
        #              Elliptic Curve 25519
        default_ike_proposals += "aes128-aes256-"
        default_ike_proposals += "md5-sha1-aesxcbc-aescmac-sha256-sha384-sha512-"
        default_ike_proposals += "prfmd5-prfsha1-prfaesxcbc-prfaescmac-prfsha256-prfsha384-prfsha512-"
        default_ike_proposals += "modp2048-modp3072-modp4096-modp6144-modp8192-ecp192-ecp224-ecp256-ecp384-ecp521-ecp224bp-ecp256bp-ecp384bp-ecp512bp-curve25519"

        # get IKE proposals from environment
        self.__ike_proposals = get_env_setting_string("IKE_PROPOSALS", default_ike_proposals)

        # ESP_PROPOSALS
        # -------------------------------------------------------------------------------------------------------------

        # ESP - Proposal 1: AEAD (encryption + integrity combined)
        # - encryption/integrity: aes[128|256][ccm|gcm][8|12|16]
        # - DH Groups: Regular Groups: modp[2048|3072|4096|6144|8192]
        #              NIST Elliptic Curve Groups: ecp[192|224|256|384|521]
        #              Brainpool Curve Groups: ecp[224|256|384|512]bp
        #              Elliptic Curve 25519
        default_esp_proposals  = "aes128gcm8-aes128gcm12-aes128gcm16-aes256gcm8-aes256gcm12-aes256gcm16-aes128ccm8-aes128ccm12-aes128ccm16-aes256ccm8-aes256ccm12-aes256ccm16-"
        default_esp_proposals += "modp2048-modp3072-modp4096-modp6144-modp8192-ecp192-ecp224-ecp256-ecp384-ecp521-ecp224bp-ecp256bp-ecp384bp-ecp512bp-curve25519,"

        # ESP - Proposal 2: Encryption + Integrity
        # - Encryption: aes[128|256]
        # - Integrity: md5, md5_128, sha1, sha1_160, aesxcbc, aescmac, sha[256|384|512]
        # - DH Groups: Regular Groups: modp[2048|3072|4096|6144|8192]
        #              NIST Elliptic Curve Groups: ecp[192|224|256|384|521]
        #              Brainpool Curve Groups: ecp[224|256|384|512]bp
        #              Elliptic Curve 25519
        default_esp_proposals += "aes128-aes256-"
        default_esp_proposals += "md5-md5_128-sha1-sha1_160-aesxcbc-aescmac-sha256-sha384-sha512-"
        default_esp_proposals += "modp2048-modp3072-modp4096-modp6144-modp8192-ecp192-ecp224-ecp256-ecp384-ecp521-ecp224bp-ecp256bp-ecp384bp-ecp512bp-curve25519"

        # get ESP proposals from environment
        self.__esp_proposals = get_env_setting_string("ESP_PROPOSALS", default_esp_proposals)

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
        self.__ca = gp_ca.CertificateAuthority()
        if not self.__ca.is_inited():
            raise gp_ca.NotInitializedError("The CA is not initialized.")
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
          "interfaces"                     : self.__interfaces,
          "vpn_hostnames"                  : self.__vpn_hostnames,
          "ca_cert_path"                   : self.__ca_cert_path,
          "ca_crl_path"                    : self.__ca_crl_path,
          "server_key_type"                : self.__server_private_key_type,   # rsa, ec
          "server_key_path"                : self.__server_key_path,
          "server_cert_path"               : self.__server_cert_path,
          "dns_servers"                    : self.__dns_servers,
          "ip_addresses_by_hostname"       : self.__ip_addresses_by_hostname,
          "ike_proposals"                  : self.__ike_proposals,
          "esp_proposals"                  : self.__esp_proposals,
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

        # generate swanctl.conf
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = SWANCTL_CONF_TEMPLATE_PATH).render(**template_context)
        with open(SWANCTL_CONF_PATH, "wt") as f:
            f.write(rendered)

        # generate strongswan.conf
        # -------------------------------------------------------------------------------------------------------------
        rendered = Template(filename = STRONGSWAN_CONF_TEMPLATE_PATH).render(**template_context)
        with open(STRONGSWAN_CONF_PATH, "wt") as f:
            f.write(rendered)

        # remount /proc/sys read-write to enable 'sysctl' to work properly
        # (only needed, if the container is not run in privileged mode)
        # -------------------------------------------------------------------------------------------------------------
        sys_proc_remounted_rw = False
        if does_mount_point_exist("/proc/sys") and is_mount_point_readonly("/proc/sys"):
            Log.write_info("Remounting /proc/sys read-write...")
            run(["mount", "-o", "remount,rw", "/proc/sys"], check=True, stdout=DEVNULL)
            sys_proc_remounted_rw = True

        # link the certificate and the CRL of the internal CA into /etc/swanctl/[x509ca|x509crl]
        # -------------------------------------------------------------------------------------------------------------
        destination_ca_crl_path = os.path.join("/etc/swanctl/x509crl", os.path.basename(self.__ca_crl_path))
        destination_ca_cert_path = os.path.join("/etc/swanctl/x509ca", os.path.basename(self.__ca_cert_path))
        if os.path.exists(destination_ca_crl_path): os.remove(destination_ca_crl_path)
        if os.path.exists(destination_ca_cert_path): os.remove(destination_ca_cert_path)
        os.symlink(self.__ca_crl_path, destination_ca_crl_path)
        os.symlink(self.__ca_cert_path, destination_ca_cert_path)

        # link the server's certificate and its private key into /etc/swanctl/[x509|private]
        # -------------------------------------------------------------------------------------------------------------
        destination_server_cert_path = os.path.join("/etc/swanctl/x509", os.path.basename(self.__server_cert_path))
        destination_server_key_path = os.path.join("/etc/swanctl/private", os.path.basename(self.__server_key_path))
        if os.path.exists(destination_server_cert_path): os.remove(destination_server_cert_path)
        if os.path.exists(destination_server_key_path): os.remove(destination_server_key_path)
        os.symlink(self.__server_cert_path, destination_server_cert_path)
        os.symlink(self.__server_key_path, destination_server_key_path)

        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        # configure networking
        # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        Log.write_info("Configuring networking...")

        # add a dummy device with an ip address for the vpn server in the client network
        run(["ip", "link", "add", "internal0", "type", "dummy"], check=True, stdout=DEVNULL)
        with open("/proc/sys/net/ipv6/conf/internal0/disable_ipv6", "w") as f: f.write("0")
        run(["ip", "-4", "addr", "add", str(self.__own_ip_in_client_subnet_ipv4) + "/" + str(self.__client_subnet_ipv4.prefixlen), "dev", "internal0"], check=True, stdout=DEVNULL)
        run(["ip", "-6", "addr", "add", str(self.__own_ip_in_client_subnet_ipv6) + "/" + str(self.__client_subnet_ipv6.prefixlen), "dev", "internal0"], check=True, stdout=DEVNULL)
        run(["ip", "link", "set", "up", "internal0"], check=True, stdout=DEVNULL)
        run(["ip", "-4", "route", "add", str(self.__own_ip_in_client_subnet_ipv4), "dev", "internal0"], check=True, stdout=DEVNULL)
        run(["ip", "-6", "route", "add", str(self.__own_ip_in_client_subnet_ipv6), "dev", "internal0"], check=True, stdout=DEVNULL)

        # enable forwarding
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, stdout=DEVNULL)
        run(["sysctl", "-w", "net.ipv6.conf.default.forwarding=1"], check=True, stdout=DEVNULL)
        run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True, stdout=DEVNULL)

        # tweak conntrack
        run(["sysctl", "-w", "net.netfilter.nf_conntrack_helper=0"], check=True, stdout=DEVNULL)                   # helpers are a security risk, if not configured properly
        run(["sysctl", "-w", "net.netfilter.nf_conntrack_tcp_loose=0"], check=True, stdout=DEVNULL)                # needed for TCP flood protection below
        # run(["sysctl", "-w", "net.netfilter.nf_conntrack_max=2000000"], check=True, stdout=DEVNULL)                # 2 million entries á 288 bytes = 576MB
        # run(["echo", "2000000", ">", "/sys/module/nf_conntrack/parameters/hashsize"], check=True, stdout=DEVNULL)  # 2 million entries á 8 bytes = 16MB

        # do not accept router advertisements on eth0, we're using a static configuration
        run(["sysctl", "-w", "net.ipv6.conf.eth0.accept_ra=0"], check=True, stdout=DEVNULL)

        # enable NDP proxying
        run(["sysctl", "-w", "net.ipv6.conf.all.proxy_ndp=1"], check=True, stdout=DEVNULL)

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

        # block bogus packets, before they can reach conntrack
        # -------------------------------------------------------------------------------------------------------------

        # allow localhost to bypass further checks for performance reasons
        iptables_add( "PREROUTING", "ACCEPT", ["-t", "raw", "-i", "lo"])
        ip6tables_add("PREROUTING", "ACCEPT", ["-t", "raw", "-i", "lo"])
        iptables_add( "PREROUTING", "ACCEPT", ["-t", "raw", "-i", "internal0"])
        ip6tables_add("PREROUTING", "ACCEPT", ["-t", "raw", "-i", "internal0"])

        # filter all packets that have RH0 headers (deprecated, can be used for DoS attacks)
        ip6tables_add("PREROUTING",  "DROP", ["-t", "raw",    "-m", "rt", "--rt-type", "0"], "RH0 Exploit Protection")
        ip6tables_add("POSTROUTING", "DROP", ["-t", "mangle", "-m", "rt", "--rt-type", "0"], "RH0 Exploit Protection")

        # prevent attacker from using the loopback address as source address
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "!", "-i", "lo", "-s", "127.0.0.0/8"], "Anti-Spoofing")
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "!", "-i", "lo", "-s", "::1/128"],     "Anti-Spoofing")

        # block TCP packets with bogus flags
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,FIN", "FIN"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,PSH", "PSH"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,URG", "URG"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "FIN,RST", "FIN,RST"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "ALL"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "NONE"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "FIN,PSH,URG"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "SYN,FIN,PSH,URG"])
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "SYN,RST,ACK,FIN,URG"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,FIN", "FIN"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,PSH", "PSH"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ACK,URG", "URG"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "FIN,RST", "FIN,RST"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "ALL"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "NONE"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "FIN,PSH,URG"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "SYN,FIN,PSH,URG"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-p", "tcp", "--tcp-flags", "ALL",     "SYN,RST,ACK,FIN,URG"])

        # prevent attacker from using a VPN client address as source address
        iptables_add( "PREROUTING", "DROP", ["-t", "raw", "-s", str(self.__client_subnet_ipv4), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")
        ip6tables_add("PREROUTING", "DROP", ["-t", "raw", "-s", str(self.__client_subnet_ipv6), "-m", "policy", "--dir", "in", "--pol", "none"], "Anti-Spoofing")

        # block all packets that have an invalid connection state
        # (mitigates all TCP flood attacks, except SYN floods)
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "PREROUTING", "DROP", ["-t", "mangle", "-m", "conntrack", "--ctstate", "INVALID"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "mangle", "-m", "conntrack", "--ctstate", "INVALID"])

        # block all packets that are new, but not SYN packets
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "PREROUTING", "DROP", ["-t", "mangle", "-p", "tcp", "!", "--syn", "-m", "conntrack", "--ctstate", "NEW"])
        ip6tables_add("PREROUTING", "DROP", ["-t", "mangle", "-p", "tcp", "!", "--syn", "-m", "conntrack", "--ctstate", "NEW"])

        # allow localhost to access everything
        # -------------------------------------------------------------------------------------------------------------
        iptables_add( "INPUT", "ACCEPT", ["-i", "lo"])
        ip6tables_add("INPUT", "ACCEPT", ["-i", "lo"])
        iptables_add( "INPUT", "ACCEPT", ["-i", "internal0"])
        ip6tables_add("INPUT", "ACCEPT", ["-i", "internal0"])

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
        iptables_add( "INPUT",   "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
        iptables_add( "FORWARD", "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
        ip6tables_add("INPUT",   "ACCEPT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"])
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
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "8", "-m", "limit", "--limit", "5/sec", "--limit-burst", "10"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "11"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "12"])
        iptables_add("AllowICMP_I", "ACCEPT", ["-p", "icmp", "--icmp-type", "30"])
        iptables_add("AllowICMP_I", "DROP")
        iptables_add("INPUT", "AllowICMP_I", ["-p", "icmp"])

        iptables_run(["-N", "AllowICMP_F"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "0"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "3"])
        iptables_add("AllowICMP_F", "ACCEPT", ["-p", "icmp", "--icmp-type", "8", "-m", "limit", "--limit", "5/sec", "--limit-burst", "10"])
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
        # Clamping' for details).
        # -------------------------------------------------------------------------------------------------------------
        mss_range = '{}:2000'.format(self.__tcp_mss + 1)
        mss = '{}'.format(self.__tcp_mss)
        iptables_run([ "-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-m", "policy", "--pol", "ipsec", "--dir", "in",
                       "-m", "tcpmss", "--mss", mss_range,
                       "-j", "TCPMSS", "--set-mss", mss])

        iptables_run([ "-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-m", "policy", "--pol", "ipsec", "--dir", "out",
                       "-m", "tcpmss", "--mss", mss_range,
                       "-j", "TCPMSS", "--set-mss", mss])

        ip6tables_run(["-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-m", "policy", "--pol", "ipsec", "--dir", "in",
                       "-m", "tcpmss", "--mss", mss_range,
                       "-j", "TCPMSS", "--set-mss", mss])

        ip6tables_run(["-t", "mangle",
                       "-A", "FORWARD",
                       "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                       "-m", "policy", "--pol", "ipsec", "--dir", "out",
                       "-m", "tcpmss", "--mss", mss_range,
                       "-j", "TCPMSS", "--set-mss", mss])

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

            self.__server_key_path  = EXTERNAL_PKI_SERVER_KEY_FILE
            self.__server_cert_path = EXTERNAL_PKI_SERVER_CERT_FILE

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
                    server_key = load_pem_private_key(f.read(), None, default_backend())

                # read server certificate
                with open(INTERNAL_PKI_SERVER_CERT_FILE, "rb") as f:
                    server_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

                if server_cert.issuer != self.__ca.cert.issuer:
                    Log.write_note("The server certificate was not issued by the internal CA. The certificate must be regenerated.")
                    create_server_cert = True

                # check whether the server certificate has expired
                if not create_server_cert:
                    if datetime.utcnow() > server_cert.not_valid_after:
                        Log.write_note("The server certificate has expired on {0}. The certificate must be regenerated.", server_cert.not_valid_after)
                        create_server_cert = True
                    elif datetime.utcnow() + timedelta(30,0,0) > server_cert.not_valid_after:
                        Log.write_note("The server certificate expires on {0}. Regenerating the certificate to ensure trouble-free operation.", server_cert.not_valid_after)
                        create_server_cert = True

                # check CN in certificate
                if not create_server_cert:
                    cert_hostname = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    expected_hostname = sans[0].split(":", 1)[1]
                    if cert_hostname != expected_hostname:
                        Log.write_warning("The server certificate was made for '{0}', but '{1}' is currently configured. The certficate must be regenerated.", cert_hostname, expected_hostname)
                        create_server_cert = True

                # check subjectAltName extension
                if not create_server_cert:
                    foundSubjectAltNameExtension = False
                    for extension in server_cert.extensions:
                        if extension.oid == x509.SubjectAlternativeName.oid:
                            expected_san = gp_ca.CertificateAuthority.build_san(sans)
                            if extension.value != expected_san:
                                Log.write_warning("Found extension 'subjectAltName', but it is '{0}', should be '{1}'.",
                                                  ", ".join([x.value for x in extension.value]),
                                                  ", ".join([x.value for x in expected_san]))
                                create_server_cert = True
                            foundSubjectAltNameExtension = True
                            break
                    if not foundSubjectAltNameExtension:
                        Log.write_note("The server certificate does not contain a 'subjectAltName' extension. The certificate must be regenerated.", server_cert_path)
                        create_server_cert = True

            # (re-)generate server credentials, if necessary
            if create_server_cert:

                # creating a new certficate requires the private key of the CA
                ca_pass = named_args["ca-pass"][0] if "ca-pass" in named_args and len(named_args["ca-pass"]) > 0 else None
                if ca_pass == None:
                    if sys.stdin.isatty():
                        ca_pass = getpass("Please enter the password of the CA: ").strip()
                    else:
                        raise gp_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")
                self.__ca.password = ca_pass

                # create new key and certificate for the VPN server
                server_key, server_cert = self.__ca.create_vpn_server_certificate(sans, server_key = None)

                # write key file
                with open(INTERNAL_PKI_SERVER_KEY_FILE, "wb+") as f:
                    f.write(server_key.private_bytes(
                        encoding = Encoding.PEM,
                        format = PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm = NoEncryption()))
                os.chown(INTERNAL_PKI_SERVER_KEY_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_KEY_FILE, S_IRUSR | S_IWUSR)

                # write certificate file
                with open(INTERNAL_PKI_SERVER_CERT_FILE, "wb+") as f:
                    f.write(server_cert.public_bytes(Encoding.PEM))
                os.chown(INTERNAL_PKI_SERVER_CERT_FILE, 0, 0)
                os.chmod(INTERNAL_PKI_SERVER_CERT_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            else:

                Log.write_info("The stored server certificate is valid and can be used as is.")

            self.__server_key_path  = INTERNAL_PKI_SERVER_KEY_FILE
            self.__server_cert_path = INTERNAL_PKI_SERVER_CERT_FILE

        # determine the type of the server's private key
        with open(INTERNAL_PKI_SERVER_KEY_FILE, "rb") as f:
            key = load_pem_private_key(f.read(), None, default_backend())
            if isinstance(key, rsa.RSAPrivateKey):
                self.__server_private_key_type = "rsa"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                self.__server_private_key_type = "ec"
            else:
                raise RuntimeError("Server key is of unhandled type.")

        # log the certificate of the VPN server
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, crypto.X509.from_cryptography(server_cert)).decode('utf-8')
        Log.write_info("Certificate of the VPN server\n{1}\n{0}\n{1}", dump, SEPARATOR_LINE)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __init_pki_for_clients(self):
        """
        """

        external_client_ca_cert_exists = os.path.exists(EXTERNAL_PKI_CLIENT_CA_CERT_FILE)

        if external_client_ca_cert_exists:

            Log.write_note("Found external CA certificate to use for client authentication.")

            self.__ca_cert_path = EXTERNAL_PKI_CLIENT_CA_CERT_FILE
            self.__ca_crl_path  = None  # get from environment (TODO)

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
        if type(error) is gp_ca.NotInitializedError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_CA_NOT_INITIALIZED
        elif type(error) is gp_ca.AlreadyInitializedError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_CA_ALREADY_INITIALIZED
        elif type(error) is gp_ca.PasswordRequiredError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_PASSWORD_REQUIRED
        elif type(error) is gp_ca.InvalidPasswordError:
            Log.write_error(error.message)
            if not Log.uses_stdio: print_error(error.message)
            return EXIT_CODE_PASSWORD_WRONG
        elif type(error) is gp_ca.InconsistencyDetectedError:
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

        return client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


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

        for index, client_cert in enumerate(client_certs):

            # get the identity the client certificate is associated with (str)
            identity = self.__get_client_certificate_identity(client_cert)

            # get start of validity period (datetime)
            notBefore = client_cert.not_valid_before

            # get end of validity period (datetime)
            notAfter = client_cert.not_valid_after

            # get revocation date (datetime or None)
            revocation_date = None
            for revoked in crl:
               if client_cert.serial_number == revoked.serial_number:
                    revocation_date = revoked.revocation_date
                    break

            # format data and store record
            record = [identity,
                      "{0:010}".format(client_cert.serial_number),
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

        # print certificates (one line per certificate)
        for index, client_cert in enumerate(client_certs):

            # get the identity the client certificate is associated with (str)
            identity = self.__get_client_certificate_identity(client_cert)

            # get start of validity period (datetime)
            notBefore = client_cert.not_valid_before

            # get end of validity period (datetime)
            notAfter = client_cert.not_valid_after

            # get revocation date (datetime or None)
            revocation_date = None
            for revoked in crl:
                if client_cert.serial_number == revoked.serial_number:
                    revocation_date = revoked.revocation_date
                    break

            # format data and store record
            record = [identity,
                      str(client_cert.serial_number),
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
        ca = gp_ca.CertificateAuthority()
        if command_requires_ca_pass:

            if ca.password_required:

                # query user to enter the CA password, if it was not specified in the command line
                if ca_pass == None:
                    if sys.stdin.isatty():
                        ca_pass = getpass("Please enter the password of the CA: ").strip()
                    else:
                        raise gp_ca.PasswordRequiredError("Please specify the CA password as command line argument or run the container in terminal mode, if you want to enter the password interactively.")

                # set the CA password
                ca.password = ca_pass  # can raise gp_ca.InvalidPasswordError

        # CA is set up properly, command can be handled
        # -----------------------------------------------------------------------------------------
        return (ca, out_format)
