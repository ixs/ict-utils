#!/usr/bin/python -tt
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

import socket
import sys
import os
try:
	import netifaces
except ImportError:
	pass
import pprint
import time
import datetime

class ICT_CC():
    """The Elmeg ICT ControlCenter handler."""

    def __init__(self, host = "192.168.1.250", port = 5003):
        """Initialize some data we need"""
        self.pbx_host = host
        self.pbx_port = port
        self.__session = ""
        self.debug = False

    def connect(self):
        """Connect to the ICT"""
        self.__session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__session.settimeout(5)
        self.__session.connect((self.pbx_host, self.pbx_port))

    def disconnect(self):
        """Disconnect from the ICT"""
        self.__session.shutdown(1)
        self.__session.close()

    def send(self, data):
        """Send data. Has optional support for debugging prints."""
        if self.debug == True:
            pprint.pprint(("tx", data))
        self.__session.send(data)

    def recv(self, buffersize):
        """Receive data. Has optional support for debugging prints."""
        data = self.__session.recv(buffersize)
        if self.debug == True:
            pprint.pprint(("rx", data))
        return data

    def discover_pbx(self):
        """Try to discover a Elmeg PBX via broadcasts"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(1)
        interfaces = netifaces.interfaces()
        s.bind(('0.0.0.0', 5000))

        resp = ("", "")
        firewall = True
        pbx = []
        for i in interfaces:
            try:
                interface = netifaces.ifaddresses(i)[2][0]
            except KeyError:
                continue
            if "broadcast" not in interface:
                continue
            s.sendto("detect router in lan by elmeg", (interface["broadcast"], 5000))
            for i in range(0,5):
                try:
                    resp = s.recvfrom(1024)
                except socket.timeout:
                    pass

                    if resp[0].startswith("detect router in lan by elmeg"):
                        # We're receiving our own query, ignore. But we know there's no firewall in place.
                        firewall = False 
                    elif resp[0].startswith("elmeg router received"):
                        pbx.append([resp[1][0], resp[0]])
                    else:
                        continue
        s.close()
        return firewall, pbx

    def status(self):
        """Get the current status of the PBX WAN interface"""
        # Message terminator is two empty CRLF lines
        self.send("STAT_REQ" + "\r\n\r\n")
        resp = ""
        while resp[-4:] != "\r\n\r\n":
            resp += self.recv(4096)

        # Parse status message
        pbx_wan_state = dict()
        for line in resp.split("\r\n"):
            if line == "":
                continue
            else:
                tmp = line.split("=")
                pbx_wan_state[tmp[0]] = tmp[1] 
        return pbx_wan_state

    def print_state(state):
        print "Router Status"
        print "%-15s%s" % ("WAN", state["WANLINK"])
        print "%-15s%s" % ("Port:", state["PORT"])
        print "%-15s%s" % ("Provider:", state["PROVIDER"])
        print "%-15s%s" % ("Dauer:", datetime.timedelta(seconds=int(state["TIME"])))
        print "%-15s%s/%s" % ("Up-/Download:", state["KBYTES_SENT"], state["KBYTES_RCVD"])
        print "%-15s%s" % ("IP-Adresse:", state["IP"])
        print "%-15s%s" % ("DNS1:", state["DNS1"])
        print "%-15s%s" % ("DNS2:", state["DNS2"])


    def ifconfig(self, state):
        if state.upper() not in ("UP", "DOWN", "HANGUP", "DIAL"):
            return False
        else:
            self.send("WANLINK\r\nACTION=%s\r\n\r\n" % (state.upper()))

class ICT_Syslog(ICT_CC):
    def __init__(self, host = "192.168.1.250", port = 5004):
        """Initialize some data we need"""
        self.pbx_host = host
        self.pbx_port = port
        self.__session = ""
        self.debug = False

        # Create a buffer to store not complete lines in
        self.buffer = ""

        # bintec syslog priorities
        self.prio = {
            8: "debug",
            12: "err",
            14: "notice",
        }
 

    def read(self, freq=2):
        while True:
            try:
                resp = self.recv(4096)
            except socket.timeout:
                pass

            # If a line is not completed, store the remainder in the buffer and then
            # join with the beginning of the next transmission
            if resp[-1] != "\n":
                resp = resp.split("\n")
                self.buffer = resp.pop()
                resp = "\n".join(resp)
            resp = self.buffer + resp
            self.buffer = ""
            print resp
            

            
if __name__ == '__main__':
    ict = ICT_Syslog("192.168.2.250")
    ict.debug = False
    ict.connect()
    ict.read()
    ict.disconnect()
