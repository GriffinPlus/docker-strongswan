"""
This module contains the command processing plugin handling VPN related commands.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os

from ..cc_log import Log
from ..cc_cmdproc import CommandProcessor


# ---------------------------------------------------------------------------------------------------------------------


# name of the processor
processor_name = 'VPN Command Processor'

# determines whether the processor is run by the startup script
enabled = True

def get_processor():
    "Returns an instance of the processor provided by the command processor plugin."
    return VpnCommandProcessor()


# ---------------------------------------------------------------------------------------------------------------------


class VpnCommandProcessor(CommandProcessor):

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

    # -------------------------------------------------------------------------------------------

    def list_clients(self, args):

        Log.write_note("TODO: listing clients... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def add_client(self, args):

        Log.write_note("TODO: add client... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def disable_client(self, args):

        Log.write_note("TODO: disabling client... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def enable_client(self, args):

        Log.write_note("TODO: enabling client... {0}".format(args))


    # -------------------------------------------------------------------------------------------


    def remove_client(self, args):

        Log.write_note("TODO: removing client... {0}".format(args))
