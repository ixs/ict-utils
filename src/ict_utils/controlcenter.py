#!/usr/bin/env python3
#
# Basic functionality to interact with an Elmeg ICT PBX.
#
# ControlCenter functionality is achieved by talking to Port 5003
#
#    Copyright (C) 2013  Andreas Thienemann <andreas@bawue.net>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the version 2 of the GNU General Public License
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

import datetime
import optparse
import pprint
import socket

import psutil


class ICT_CC:
    """The Elmeg ICT ControlCenter handler."""

    def __init__(self, host="192.168.1.250", port=5003):
        self.pbx_host = host
        self.pbx_port = port
        self._session: socket.socket | None = None
        self.debug = False

    def connect(self):
        self._session = socket.create_connection(
            (self.pbx_host, self.pbx_port), timeout=5
        )

    def disconnect(self):
        assert self._session is not None, "Not connected"
        self._session.shutdown(socket.SHUT_WR)
        self._session.close()

    def send(self, data: str):
        if self.debug:
            pprint.pprint(("tx", data))
        assert self._session is not None, "Not connected"
        self._session.sendall(data.encode("latin-1"))

    def recv(self, buffersize: int) -> str:
        assert self._session is not None, "Not connected"
        data = self._session.recv(buffersize)
        if not data:
            raise ConnectionError("PBX closed the connection")
        if self.debug:
            pprint.pprint(("rx", data))
        return data.decode("latin-1")

    def discover_pbx(self):
        """Try to discover an Elmeg PBX on each IPv4 broadcast interface."""
        firewall = True
        pbx = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as session:
            session.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            session.settimeout(1)
            session.bind(("0.0.0.0", 5000))
            for addresses in psutil.net_if_addrs().values():
                for address in addresses:
                    if address.family != socket.AF_INET or not address.broadcast:
                        continue
                    session.sendto(
                        b"detect router in lan by elmeg", (address.broadcast, 5000)
                    )
                    for _ in range(5):
                        try:
                            data, sender = session.recvfrom(1024)
                        except TimeoutError:
                            continue
                        if data.startswith(b"detect router in lan by elmeg"):
                            firewall = False
                        elif data.startswith(b"elmeg router received"):
                            pbx.append([sender[0], data.decode("latin-1")])
        return firewall, pbx

    def status(self):
        """Get the current status of the PBX WAN interface."""
        self.send("STAT_REQ\r\n\r\n")
        response = ""
        while not response.endswith("\r\n\r\n"):
            response += self.recv(4096)
        return dict(line.split("=", 1) for line in response.split("\r\n") if line)

    @staticmethod
    def print_state(state):
        print("Router Status")
        print("{:<15}{}".format("WAN", state["WANLINK"]))
        print("{:<15}{}".format("Port:", state["PORT"]))
        print("{:<15}{}".format("Provider:", state["PROVIDER"]))
        print(
            "{:<15}{}".format("Dauer:", datetime.timedelta(seconds=int(state["TIME"])))
        )
        print(
            "{:<15}{}/{}".format(
                "Up-/Download:", state["KBYTES_SENT"], state["KBYTES_RCVD"]
            )
        )
        print("{:<15}{}".format("IP-Adresse:", state["IP"]))
        print("{:<15}{}".format("DNS1:", state["DNS1"]))
        print("{:<15}{}".format("DNS2:", state["DNS2"]))

    def ifconfig(self, state):
        if state.upper() not in ("UP", "DOWN", "HANGUP", "DIAL"):
            return False
        self.send(f"WANLINK\r\nACTION={state.upper()}\r\n\r\n")


class ICT_Syslog(ICT_CC):
    def __init__(self, host="192.168.1.250", port=5004):
        super().__init__(host, port)
        self.buffer = ""
        self.prio = {8: "debug", 12: "err", 14: "notice"}

    def read(self, freq=2):
        while True:
            try:
                response = self.recv(4096)
            except TimeoutError:
                continue
            lines = (self.buffer + response).split("\n")
            self.buffer = lines.pop()
            for line in lines:
                print(line)


def main():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option(
        "-i", "--ip", dest="host", default="192.168.1.250", help="PBX IP address"
    )
    parser.add_option(
        "-d", "--debug", action="store_true", default=False, help="Dump every packet"
    )
    opts, args = parser.parse_args()
    if args:
        parser.error("No positional arguments expected")
    ict = ICT_Syslog(opts.host)
    ict.debug = opts.debug
    ict.connect()
    try:
        ict.read()
    except KeyboardInterrupt:
        pass
    finally:
        ict.disconnect()


if __name__ == "__main__":
    main()
