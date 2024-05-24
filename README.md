# prometheus-tor_exporter

Prometheus exporter for the TOR daemon. (Fork with container)

![prometheus-tor-exporter](https://user-images.githubusercontent.com/3966931/27349994-5cec464c-55f9-11e7-805a-2aea50413f2a.png)

_(the JSON descriptor file for this dashboard can be
found [here](https://gist.github.com/atx/f4d12616eaac919b6764109ffd470c99))_

## Usage

``docker run ghcr.io/h3rmt/tor-exporter:latest -m tcp -a 127.0.0.1 -c 9051 -b 0.0.0.0 -p 9099``

## Configuration

The parameters can be listed py running `prometheus-tor-exporter.py -h`

```
usage: prometheus-tor-exporter.py [-h] [-m {tcp,unix}] [-a ADDRESS]
                                  [-c CONTROL_PORT] [-s CONTROL_SOCKET]
                                  [-p LISTEN_PORT] [-b BIND_ADDR]

optional arguments:
  -h, --help            show this help message and exit
  -m {tcp,unix}, --mode {tcp,unix}
                        Tor socker control mode (tcp or unix, default tcp)
  -a ADDRESS, --address ADDRESS
                        Tor control IP address
  -c CONTROL_PORT, --control-port CONTROL_PORT
                        Tor control port
  -s CONTROL_SOCKET, --control-socket CONTROL_SOCKET
                        Tor control socket
  -p LISTEN_PORT, --listen-port LISTEN_PORT
                        Listen on this port
  -b BIND_ADDR, --bind-addr BIND_ADDR
                        Bind this address
```

The password (if any) used to authenticate to the Tor control socket is read
from the environment variable `PROM_TOR_EXPORTER`.

## Exported metrics

| Name                                                                                                                                                                   | Description                                                                                                       |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| tor_written_bytes                                                                                                                                                      | Running total of written bytes                                                                                    |
| tor_read_bytes                                                                                                                                                         | Running total of read bytes                                                                                       |
| tor_version{version="..."}                                                                                                                                             | Tor daemon version as a tag                                                                                       |
| tor_version_status={version_status="..."}                                                                                                                              | Tor daemon version status as a tag                                                                                |
| tor_network_liveness                                                                                                                                                   | Network liveness (1.0 or 0.0)                                                                                     |
| tor_reachable{port="OR\|DIR"}                                                                                                                                          | Reachability of the OR/DIR ports (1.0 or 0.0)                                                                     |
| tor_circuit_established                                                                                                                                                | Indicates whether the daemon is capable of establishing circuits (1.0 or 0.0)                                     |
| tor_enough_dir_info                                                                                                                                                    | Indicates whether the daemon has enough directory information (1.0 or 0.0)                                        |
| tor_dormant                                                                                                                                                            | Indicates whether tor is currently active (1.0 or 0.0) (note that 1.0 means "dormant", see the specs for details) |
| tor_effective_rate                                                                                                                                                     | Shows the effective rate of the relay                                                                             |
| tor_effective_burst_rate                                                                                                                                               | Shows the effective burst rate of the relay                                                                       |
| tor_fingerprint{fingerprint="..."}                                                                                                                                     | Node fingerprint as a tag                                                                                         |
| tor_nickname{nickname="..."}                                                                                                                                           | Node nickname as a tag                                                                                            |
| tor_flags{flag="Authority\|BadExit\|BadDirectory\|Exit\|<br/>Fast\|Guard\|HSDir\|Named\|NoEdConsensus\|Running\|<br/>Stable\|StaleDesc\|Unnamed\|V2Dir\|V3Dir\|Valid"} | Indicates whether the node has a certain flag (1.0 or 0.0)                                                        |
| tor_bridge_clients_seen{country="..."}                                                                                                                                 | Tor bridge clients per country. Reset every 24 hours and only increased by multiples of 8                         |
| tor_accounting_read_bytes                                                                                                                                              | Amount of bytes read in the current accounting period                                                             |
| tor_accounting_left_read_bytes                                                                                                                                         | Amount of read bytes left in the current accounting period                                                        |
| tor_accounting_read_limit_bytes                                                                                                                                        | Read byte limit in the current accounting period                                                                  |
| tor_accounting_write_bytes                                                                                                                                             | Amount of bytes written in the current accounting period                                                          |
| tor_accounting_left_write_bytes                                                                                                                                        | Amount of write bytes left in the current accounting period                                                       |
| tor_accounting_write_limit_bytes                                                                                                                                       | Write byte limit in the current accounting period                                                                 |
| tor_uptime                                                                                                                                                             | Uptime of the tor process (in seconds)                                                                            |
| tor_address                                                                                                                                                            | Ipv4 and Ipv6 Addresses of Tor                                                                                    |
| tor_descriptor_limit                                                                                                                                                   | Upper bound on the file descriptor limit, -1if unknown                                                            |

A more in-depth explanation of the various variables can be found in
the [control port manual](https://gitweb.torproject.org/torspec.git/tree/control-spec.txt)
