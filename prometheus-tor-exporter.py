import argparse
import logging
import os
import re
import sys

from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily as Metric, REGISTRY
from retrying import retry
from stem import ProtocolError, OperationFailed, DescriptorUnavailable, ControllerError
from stem.connection import IncorrectPassword
from stem.control import Controller
from stem.util.connection import get_connections

PASSWORD_ENV = "PROM_TOR_EXPORTER_PASSWORD"


class StemCollector:
    def __init__(self, tor: Controller):
        self.tor = tor
        self.password = os.environ.get(PASSWORD_ENV, "")
        self.authenticate()

    @retry(wait_random_min=1000, wait_random_max=2000, stop_max_attempt_number=5)
    def authenticate(self):
        try:
            self.tor.authenticate(password=self.password)
        except IncorrectPassword:
            logging.error("Failed password authentication to the Tor control socket.\n"
                          "The password is read from the environment variable "
                          "{}.".format(PASSWORD_ENV))
            sys.exit(1)

    @retry(wait_random_min=1000, wait_random_max=2000, stop_max_attempt_number=5)
    def reconnect(self):
        try:
            self.tor.reconnect(password=self.password)
        except IncorrectPassword:
            logging.error("Failed password authentication to the Tor control socket.\n"
                          "The password is read from the environment variable "
                          "{}.".format(PASSWORD_ENV))
            sys.exit(1)

    # https://github.com/torproject/torspec/blob/main/control-spec.txt
    def collect(self):
        if not self.tor.is_authenticated():
            logging.info("reconnecting...")
            self.reconnect()

        try:
            address_metric = Metric("tor_address", "Ipv4 and Ipv6 Addresses of Tor", labels=["address", "type"])
            address_metric.add_metric([self.tor.get_info("address/v4"), "Ipv4"], 1)
            address_metric.add_metric([self.tor.get_info("address/v6"), "Ipv6"], 1)
            yield address_metric
        except OperationFailed as e:
            logging.debug("No Addresses found: %s", e)

        yield Metric("tor_descriptor_limit", "Upper bound on the file descriptor limit",
                     value=int(self.tor.get_info("process/descriptor-limit")))
        yield Metric("tor_uptime", "Tor daemon uptime in seconds", value=int(self.tor.get_info("uptime")))
        yield Metric("tor_written_bytes_total", "Tor written data counter",
                     value=int(self.tor.get_info("traffic/written")))
        yield Metric("tor_read_bytes_total", "Tor received data counter", value=int(self.tor.get_info("traffic/read")))

        version = Metric("tor_version", "Tor version as a label", labels=["version"])
        version.add_metric([str(torctl.get_version())], 1)
        yield version

        version_status = Metric("tor_version_status", "Tor version status {new, old, unrecommended, "
                                                      "recommended, new in series, obsolete, unknown} as a "
                                                      "label", labels=["version_status"], )
        version_status.add_metric([self.tor.get_info("status/version/current")], 1)
        yield version_status

        yield Metric("tor_network_liveness", "Indicates whether tor believes that the network is currently reachable",
                     value=int(self.tor.get_info("network-liveness") == "up"))

        reachable = Metric("tor_reachable", "Indicates whether tor OR/Dir port is reachable", labels=["port"])
        for entry in self.tor.get_info("status/reachability-succeeded").split():
            k, v = entry.split("=")
            reachable.add_metric([k], int(v))
        yield reachable

        yield Metric("tor_circuit_established", "Indicates whether Tor is capable of establishing circuits",
                     value=int(self.tor.get_info("status/circuit-established")))
        yield Metric("tor_enough_dir_info", "Indicates whether Tor has enough directory information",
                     value=int(self.tor.get_info("status/enough-dir-info")))

        # For some reason, 0 actually means that Tor is active.
        # Keep it that way.
        yield Metric("tor_dormant",
                     "Indicates whether Tor is currently active and building circuits (note that 0 corresponds to Tor "
                     "being active)", value=int(self.tor.get_info("dormant")))

        effective_rate = self.tor.get_effective_rate(None)
        effective_burst_rate = self.tor.get_effective_rate(None, burst=True)
        if effective_rate is not None and effective_burst_rate is not None:
            yield Metric("tor_effective_rate", "Tor effective bandwidth rate", value=int(effective_rate))
            yield Metric("tor_effective_burst_rate", "Tor effective burst bandwidth rate",
                         value=int(effective_burst_rate))

        try:
            fingerprint_value = self.tor.get_info("fingerprint")
            fingerprint = Metric("tor_fingerprint", "Tor server fingerprint as a label", labels=["fingerprint"], )
            fingerprint.add_metric([fingerprint_value], 1)
            yield fingerprint
        except (ProtocolError, OperationFailed) as e:
            logging.debug("No Fingerprint found: %s", e)
            pass  # happens when not running in server mode

        nickname = Metric("tor_nickname", "Tor nickname as a label", labels=["nickname"])
        nickname.add_metric([self.tor.get_conf("Nickname", "Unnamed")], 1)
        yield nickname

        # Connection counting
        # This won't work/will return wrong results if we are not running on
        # the same box as the Tor daemon is.
        # DisableDebuggerAttachment has to be set to 0
        # TODO: Count individual OUT/DIR/Control connections, see arm sources
        # for reference
        try:
            tor_pid = self.tor.get_pid()
            logging.debug("Tor Pid: %s", tor_pid)
            connections = get_connections(process_pid=tor_pid)
            yield Metric("tor_connection_count", "Amount of connections the Tor daemon has open",
                         value=len(connections))
        except (OSError, IOError) as e:
            logging.debug("Pid not found: %s", e)
            pass  # This happens if the PID does not exist (on another machine).

        try:
            has_flags = self.tor.get_network_status().flags
        except DescriptorUnavailable as e:
            # The tor daemon fails with this for a few minutes after startup
            # (before figuring out its own flags?)
            logging.debug("Descriptors not available (tor to young): %s", e)
            has_flags = []
        except ControllerError as e:
            # Happens when the daemon is not running in server mode
            logging.debug("Descriptors not available (server mode): %s", e)
            has_flags = []

        logging.debug("Flags: %s", has_flags)
        flags = Metric("tor_flags", "Has a Tor flag", labels=["flag"])
        for flag in ["Authority", "BadExit", "BadDirectory", "Exit", "Fast", "Guard", "HSDir", "Named", "NoEdConsensus",
                     "Running", "Stable", "StaleDesc", "Unnamed", "V2Dir", "V3Dir", "Valid"]:
            flags.add_metric([flag], int(flag in has_flags))
        yield flags

        regex = re.compile(".*CountrySummary=([a-z0-9=,]+)")
        country_summary = regex.match(self.tor.get_info("status/clients-seen"))
        if country_summary is not None:
            logging.debug("Countries: %s", country_summary.group(1))
            country_summary_split = country_summary.group(1).split(",")
            bridge_clients_seen = Metric("tor_bridge_clients_seen",
                                         "Tor bridge clients per country. Reset every 24 hours and only increased by "
                                         "multiples of 8.", labels=["country"])
            for country in country_summary_split:
                bridge_clients_seen.add_metric(country[:2], country[3:])
            yield bridge_clients_seen

        try:
            stats = self.tor.get_accounting_stats()
            yield Metric("tor_accounting_read_bytes", "Tor accounting read bytes", stats.read_bytes)
            yield Metric("tor_accounting_left_read_bytes", "Tor accounting read bytes left", stats.read_bytes_left)
            yield Metric("tor_accounting_read_limit_bytes", "Tor accounting read bytes limit", stats.read_limit)
            yield Metric("tor_accounting_write_bytes", "Tor accounting write bytes", stats.written_bytes)
            yield Metric("tor_accounting_left_write_bytes", "Tor accounting write bytes left", stats.write_bytes_left)
            yield Metric("tor_accounting_write_limit_bytes", "Tor accounting write bytes limit", stats.write_limit)
        except ControllerError as e:
            logging.debug("Accounting isn't enabled: %s", e)
            pass  # happens when accounting isn't enabled
        logging.debug("collection finished\n")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'INFO').upper())
    logging.getLogger('stem').setLevel(os.environ.get('LOGLEVEL_STEM', "WARNING").upper())
    parser = argparse.ArgumentParser()

    parser.add_argument("-m", "--mode", help="Tor socker control mode (tcp or unix, default tcp)", default="tcp",
                        choices=["tcp", "unix"])
    parser.add_argument("-a", "--address", help="Tor control IP address", default="127.0.0.1")
    parser.add_argument("-c", "--control-port", help="Tor control port", type=int, default=9051)
    parser.add_argument("-s", "--control-socket", help="Tor control socket", default="/var/run/tor/control")
    parser.add_argument("-p", "--listen-port", help="Listen on this port", type=int, default=9099)
    parser.add_argument("-b", "--bind-addr", help="Bind this address", default="localhost")
    args = parser.parse_args()

    if args.mode == "unix":
        torctl = Controller.from_socket_file(args.control_socket)
    else:
        torctl = Controller.from_port(args.address, port=args.control_port)
    REGISTRY.register(StemCollector(torctl))

    server, thread = start_http_server(args.listen_port, addr=args.bind_addr)
    logging.info("Starting on %s:%s" % (server.server_address, server.server_port))
    thread.join()
