"""
  retrieves ansible public & private keys from vault, and hav Vault sign
  the public Key in order to enable Ansible to connect to managed hosts

  Before retrieving any key, VAULT_TOKEN environment variable must have
  been set. For that purpose, the get_vault_token.py script might be usefull.

  WARNING: keys should never be stored outside of a ephemeral container
"""

import configparser
import json
import logging
import logging.handlers
from os import path
from sys import exit as sysexit

from logging_ldp.formatters import LDPGELFFormatter
from logging_ldp.handlers import LDPGELFTCPSocketHandler
from logging_ldp.schemas import LDPSchema
from marshmallow import Schema, fields


class Request(Schema):
    client_ip = fields.Str(default="")
    client_auth = fields.Str(default="")
    request_time = fields.Str(default="")
    request = fields.Str(default="")
    method = fields.Str(default="")
    destination = fields.Str(default="")
    error_message = fields.Str(default="")


class RequestInfo(LDPSchema):
    """
    Represents a request deserialized from log entry
    """

    request = fields.Nested(Request)
    error_message = fields.Str()


class LogSender:
    """
    Sends log from trafficserver to OVH-LDP
    """

    # --------------------
    def __init__(self):
        """
        Constructor
        """
        self.config = None
        self.ldp_logger = None
        self.logger = logging.getLogger("LogSender")
        sysloghandler = logging.handlers.SysLogHandler(address="/dev/log")
        self.logger.addHandler(sysloghandler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.warning("Starting LogSender")

    # --------------------
    def load_config(self):
        """
        load config from ini file
        """
        # ----------------------------------------------------------------
        # - Config Files
        __CFG_FILE_NAME = "/etc/trafficserver/log_sender.ini"

        # Config Path enables using an external config file
        self.config = configparser.ConfigParser(interpolation=None)

        try:
            if path.exists(__CFG_FILE_NAME):
                self.config.read(__CFG_FILE_NAME)
            else:
                self.logger.warning("No config file found")
        except configparser.Error:
            pass

    # --------------------
    def setup_logging(self):
        """
        Configure logging => sending to LDP
        """
        handler = LDPGELFTCPSocketHandler(
            hostname=self.config.get("OVH", "host", fallback="gra3.logs.ovh.com")
        )
        handler.setFormatter(
            LDPGELFFormatter(
                token=self.config.get("OVH", "token", fallback=False),
                schema=RequestInfo,
            )
        )
        self.ldp_logger = logging.getLogger("LDP_Sender")
        self.ldp_logger.addHandler(handler)
        self.ldp_logger.setLevel(logging.INFO)

    # --------------------
    def sendloop(self):
        """
        never stops and send logs from pipe to LDP
        """

        fifo_filename = self.config.get(
            "SENDER", "pipe_file", fallback="/var/log/trafficserver/event_pipe.pipe"
        )

        if path.exists(fifo_filename):
            self.logger.warning("Starting LogSender Loop")
            with open(fifo_filename) as afifo:
                schema = Request()
                for line in afifo:
                    try:
                        json_log = json.loads(line)
                        dest = json_log.get("destination", "Unknown")
                        log_entry = schema.load(json_log)
                        self.ldp_logger.info(
                            dest, extra=dict(request=log_entry, error_message="")
                        )
                    except Exception as err:
                        self.logger.exception(f"failed to parse: {line} => {err}")
                        self.ldp_logger.warning(
                            line, extra=dict(error_message=str(err))
                        )
            return 0
        else:
            self.logger.warning("Could not open event_pipe file")
            return -1


if __name__ == "__main__":
    logsender = LogSender()
    logsender.load_config()
    logsender.setup_logging()
    sysexit(logsender.sendloop())
