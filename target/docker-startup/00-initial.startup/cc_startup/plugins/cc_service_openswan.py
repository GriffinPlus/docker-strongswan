"""
This module contains everything needed to configure 'openswan'.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import os
import re

from configparser import ConfigParser
from ..cc_helpers import read_text_file, write_text_file, replace_php_define, replace_php_variable, generate_password, get_env_setting_bool, get_env_setting_integer, get_env_setting_string
from ..cc_log import Log
from ..cc_service import Service


# ---------------------------------------------------------------------------------------------------------------------


CONFIGURATION_FILE_PATH = 'TODO'


# ---------------------------------------------------------------------------------------------------------------------


# name of the service
service_name = 'openswan'

# determines whether the service is run by the startup script
enabled = True

def get_service():
    "Returns an instance of the service provided by the service plugin."
    return Openswan()


# ---------------------------------------------------------------------------------------------------------------------


class Openswan(Service):

    def prepare(self):
        """
        Reads environment variables and checks preconditions the following call to configure() needs to succeed. In case
        of anything being screwed in the configuration or system, this method should throw an exception to abort starting
        up before configure() modifies any configuration files.
        """

        # load configuration file
        # ---------------------------------------------------------------------------------------

        pass


    # ---------------------------------------------------------------------------------------------------------------------


    def configure(self):
        """
        Creates/modifies the configuration file according to environment variables.
        """

        # write configuraton file
        # ---------------------------------------------------------------------------------------

        pass

    # ---------------------------------------------------------------------------------------------------------------------


