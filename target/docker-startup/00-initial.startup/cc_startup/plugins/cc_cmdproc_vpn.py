"""
This module contains the command processing plugin handling VPN related commands.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
from OpenSSL import crypto, SSL

from ..cc_log import Log
from ..cc_cmdproc import CommandProcessor
from .cc_ca import CertificateAuthority

# ---------------------------------------------------------------------------------------------------------------------


# name of the processor
processor_name = 'VPN Command Processor'

# determines whether the processor is run by the startup script
enabled = True

def get_processor():
    "Returns an instance of the processor provided by the command processor plugin."
    return VpnCommandProcessor()


# ---------------------------------------------------------------------------------------------------------------------


# line used to separate blocks of information in the log
SEPARATOR_LINE = "----------------------------------------------------------------------------------------------------------------------"


# ---------------------------------------------------------------------------------------------------------------------


class VpnCommandProcessor(CommandProcessor):

    # -------------------------------------------------------------------------------------------

    _ca = None

    # -------------------------------------------------------------------------------------------


    def __init__(self):

        # let base class perform its initialization
        super().__init__()

        # register command handlers
        self._handlers.append((self.list_clients,   ( "list",    "clients" ) ))
        self._handlers.append((self.add_client,     ( "add",     "client"  ) ))
        self._handlers.append((self.disable_client, ( "disable", "client"  ) ))
        self._handlers.append((self.enable_client,  ( "enable",  "client"  ) ))
        self._handlers.append((self.remove_client,  ( "remove",  "client"  ) ))

        # initialize the CA that is needed to process requests
        self._ca = CertificateAuthority()

    # -------------------------------------------------------------------------------------------

    def list_clients(self, args):

        Log.write_note("TODO: listing clients... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def add_client(self, args):

        if len(args) != 4:
            raise RuntimeError("Expecting 4 parameters, you specified {0} ({1})".format(len(args), args))

        identity = args[2]
        password = args[3]

        Log.write_note("Adding client ({0})... {0}".format(identity))
        data = self._ca.create_vpn_client_data(identity, password)

        # log the generated PKCS12 archive 
        dump = crypto.dump_certificate(crypto.FILETYPE_TEXT, data["certificate"]).decode('utf-8')
        Log.write_note("Certificate of the VPN client\n{1}\n{0}\n{1}".format(dump, SEPARATOR_LINE))


    # -------------------------------------------------------------------------------------------


    def disable_client(self, args):

        Log.write_note("TODO: disabling client... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def enable_client(self, args):

        Log.write_note("TODO: enabling client... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def remove_client(self, args):

        Log.write_note("TODO: removing client... {0}".format(args))
