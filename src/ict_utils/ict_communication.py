#!/usr/bin/env python3
#
# Basic functionality to interact with an Elmeg ICT PBX.
#
# Professional Configurator functionality is achieved by talking to port 5000
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
#

import pprint
import socket
import struct
from array import array
from collections.abc import Iterable


class ICT_Comm:
    """The Elmeg ICT Communication class."""

    def __init__(self, host="192.168.1.250", user="Service", pwd="Service"):
        """Initialize some data we need"""
        self.pbx_host = host
        self.pbx_port = 5000
        self.pbx_user = user.encode("latin-1")
        self.pbx_pass = pwd.encode("latin-1")
        self.__session: socket.socket | None = None
        self.debug = False

    def connect(self):
        """Connect to the ICT"""
        self.__session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__session.settimeout(5)
        self.__session.connect((self.pbx_host, self.pbx_port))

    def disconnect(self):
        """Disconnect from the ICT"""
        assert self.__session is not None, "Not connected"
        self.__session.shutdown(1)
        self.__session.close()

    def send(self, data: bytes):
        """Send data. Has optional support for debugging prints."""
        if self.debug:
            pprint.pprint(("tx", data))
        assert self.__session is not None, "Not connected"
        self.__session.sendall(data)

    def recv(self, buffersize: int = 4096) -> bytes:
        """Receive one complete BCC packet, even across TCP reads."""
        assert self.__session is not None, "Not connected"
        data = bytearray()
        length = 5
        while len(data) < length:
            part = self.__session.recv(min(buffersize, length - len(data)))
            if not part:
                raise ConnectionError("PBX closed the connection")
            data.extend(part)
            if len(data) == 5:
                if not data.startswith(b"BCC"):
                    raise RuntimeError("ParseError: Invalid packet prefix")
                length = 5 + struct.unpack("!h", data[3:5])[0]
                if length < 6:
                    raise RuntimeError("ParseError: Invalid packet length")
        if self.debug:
            pprint.pprint(("rx", bytes(data)))
        return bytes(data)

    def prepare_packet(self, cmd: Iterable[int], payload: bytes | None = None) -> bytes:
        """Prepare the package to be sent.
        (3) BCC Prefix
        (2) Total data length
        (1) Command data length
        (x) Command data
        (x) Payload
        """
        # Packet header - BCC fixed string
        header = (0x42, 0x43, 0x43)
        header = array("B", header)

        # Command instruction
        cmd = array("B", cmd)
        cmd_len = len(cmd)

        # Payload
        if payload is not None:
            payload_len = len(payload)
            payload_fmt = str(payload_len) + "s"
        else:
            payload_len = 0
            payload_fmt = "0s"
            payload = b""

        # total length
        total_len = cmd_len + 1 + payload_len

        # pack format string (Network byte order)
        fmt = "!" + "3s" + "h" + "b" + str(len(cmd)) + "s" + payload_fmt

        packet = struct.pack(
            fmt, header.tobytes(), total_len, cmd_len, cmd.tobytes(), payload
        )
        return packet

    def prepare_payload(self, payload: bytes) -> bytes:
        """Prepare the payload to be added to a package.
        (2) Total payload length
        (x) Payload
        """
        # Payload
        payload_len = len(payload)
        payload_fmt = str(payload_len) + "s"

        # pack format string (Network byte order)
        fmt = "!" + "h" + payload_fmt

        packet = struct.pack(fmt, payload_len, payload)
        return packet

    def chunk_data(self, pack_length: int, data: bytes) -> bytes:
        """Build chunks for elmeg communication"""
        lengths = {
            1: "B",
            2: "H",
            4: "L",
        }
        data_len = len(data)
        data_fmt = str(data_len) + "s"
        # pack format string (Network byte order)
        fmt = "!" + lengths[pack_length] + data_fmt
        return struct.pack(fmt, data_len, data)

    def dechunk_data(self, data: bytes) -> list[bytes]:
        chunks = []
        data_len = len(data)
        pos = 0
        while pos < data_len:
            chunk_len = data[pos]
            if pos + 1 + chunk_len > data_len:
                raise ValueError("Truncated chunk")
            chunks.append(data[pos + 1 : pos + 1 + chunk_len])
            pos = pos + chunk_len + 1
        return chunks

    def parse_packet(self, data: bytes) -> bytes:
        if len(data) < 6 or not data.startswith(b"BCC"):
            raise RuntimeError(
                "ParseError: Prefix indicates not an Elmeg response packet"
            )
        pckt_header = struct.unpack("!3shb", data[:6])

        # Subtract the prefix (3bytes) plus the length of the length field itself (2bytes) from the payload-length
        if not len(data) - 5 == pckt_header[1]:
            raise RuntimeError("ParseError: Short packet detected")

        return data[6:]

    def init(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array("B", (0x02, 0x02, 0x00)).tobytes():
            raise RuntimeError(
                "CommunicationError: Could not initiate handshake with PBX "
            )

    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array("B", (0x02, 0x02, 0x00)).tobytes():
            raise RuntimeError(
                "CommunicationError: Could not initiate handshake with PBX "
            )

        payload = array("B", (0x01, 0x00, 0x05, 0x00, 0x01, 0x0B))
        # Chunk index
        payload.append(0x01)
        payload.frombytes(struct.pack("!h", len(self.pbx_user) + 1))
        payload.frombytes(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.frombytes(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.frombytes(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == 0x01:
            raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def logout(self):
        payload = array("B", (0x02, 0x01, 0x05, 0x00, 0x01, 0x0B))
        # Chunk index
        payload.append(0x01)
        payload.frombytes(struct.pack("!h", len(self.pbx_user) + 1))
        payload.frombytes(self.pbx_user)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == 0x01:
            raise RuntimeError("CommunicationError: Could not logout off PBX ")
        return True

    def pabx_ping(self):
        payload = array("B", (0x03, 0x01, 0x1B, 0x00, 0x00))

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        return self.parse_packet(resp)[9:].decode("latin-1").replace("\x00", " ")[:-1]

    def erase_lcr(self):
        file = b"LCR.XML"
        payload = array("B", (0x03, 0x01, 0x25, 0x10, 0x00, 0x07, 0x01, 0x06, 0x05))
        payload.frombytes(struct.pack("!B", len(file)))
        payload.append(0x00)
        payload.frombytes(file)
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        if (
            self.parse_packet(resp)
            != array(
                "B", (0xF0, 0x80, 0x00, 0x05, 0x03, 0x01, 0x25, 0x00, 0x00)
            ).tobytes()
        ):
            raise RuntimeError("CommunicationError: Unexpected data received")
        else:
            return True

    def get_lcr(self):
        file = b"webpages/xml/lcr.xml"
        payload = array(
            "B", (0x03, 0x01, 0x26, 0x00, 0x1A, 0x04, 0x07, 0x01, 0x06, 0x05)
        )
        payload.frombytes(struct.pack("!B", len(file)))
        payload.frombytes(file)
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        # Is the xml data following this packet?
        if (
            self.parse_packet(resp)
            == array(
                "B", (0xF0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x26, 0x00, 0x02, 0x00, 0x05)
            ).tobytes()
        ):
            xml_data = b""
            while True:
                try:
                    resp = self.recv()
                    data = self.parse_packet(resp)
                    # Get the sequence number
                    seq = data[11]
                    # Get the xml_data
                    xml_data += data[12:]
                    # Ack the packet
                    payload = array("B", (0x03, 0x01, 0x28, 0x00, 0x03, 0x00, 0x00))
                    payload.frombytes(struct.pack("!B", seq))
                    packet = self.prepare_packet(
                        (0xF0, 0x80), self.prepare_payload(payload.tobytes())
                    )
                    self.send(packet)
                    # This might be an end of transmission marker
                    # 0x05 first packet, 0x04 further data, 0x06 end of data
                    if data[9] == 0x06:
                        break
                except TimeoutError:
                    raise RuntimeError("CommunicationError: Incomplete LCR download")
        elif (
            self.parse_packet(resp)
            == array(
                "B", (0xF0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x26, 0x00, 0x02, 0x51, 0x00)
            ).tobytes()
        ):
            # print "No LCR data available on the PBX"
            return False
        else:
            raise RuntimeError("CommunicationError: Unexpected data received")
        return xml_data

    def put_lcr(self, xml_data: bytes):
        file = b"LCR.XML"
        payload = array(
            "B", (0x03, 0x01, 0x27, 0x00, 0x0E, 0x04, 0x07, 0x01, 0x06, 0x05)
        )
        payload.frombytes(struct.pack("!B", len(file)))
        payload.frombytes(file)
        payload.append(0x00)
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        # Is the PBX ready for upload?
        if (
            self.parse_packet(resp)
            == array(
                "B", (0xF0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x27, 0x00, 0x02, 0x00, 0x05)
            ).tobytes()
        ):
            seq = 0
            while len(xml_data) > 0:
                # Get data to transmit in nice 512byte chunks
                tx = xml_data[:512]
                xml_data = xml_data[512:]
                try:
                    payload = array("B", (0x03, 0x01, 0x29))
                    payload.frombytes(struct.pack("!h", len(tx) + 3))
                    if len(xml_data) == 0:
                        payload.append(0x06)
                    elif seq == 0:
                        payload.append(0x05)
                    else:
                        payload.append(0x04)
                    payload.append(0x00)
                    payload.frombytes(struct.pack("!B", seq))
                    payload.frombytes(tx)
                    packet = self.prepare_packet(
                        (0xF0, 0x80), self.prepare_payload(payload.tobytes())
                    )
                    self.send(packet)
                    # Check for ack
                    resp = self.recv()
                    if self.parse_packet(resp) == array(
                        "B",
                        (
                            0xF0,
                            0x80,
                            0x00,
                            0x08,
                            0x03,
                            0x01,
                            0x29,
                            0x00,
                            0x03,
                            0x00,
                            0x00,
                        ),
                    ).tobytes() + bytes((seq,)):
                        seq += 1
                    elif self.parse_packet(resp) == array(
                        "B",
                        (
                            0xF0,
                            0x80,
                            0x00,
                            0x08,
                            0x03,
                            0x01,
                            0x29,
                            0x00,
                            0x03,
                            0x03,
                            0x00,
                        ),
                    ).tobytes() + bytes((seq,)):
                        # print "Cannot write LCR data, LCR data already present."
                        return False
                    else:
                        raise RuntimeError(
                            "CommunicationError: Unexpected data received"
                        )
                except TimeoutError:
                    raise RuntimeError("CommunicationError: Incomplete LCR upload")
        else:
            raise RuntimeError("CommunicationError: Unexpected data received")
        return True


class ICT_StatusComm(ICT_Comm):
    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array("B", (0x02, 0x02, 0x00)).tobytes():
            raise RuntimeError(
                "CommunicationError: Could not initiate handshake with PBX "
            )

        payload = array("B", (0x01, 0x00, 0x05, 0x00, 0x01, 0x01))
        # Chunk index
        payload.append(0x01)
        payload.frombytes(struct.pack("!h", len(self.pbx_user) + 1))
        payload.frombytes(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.frombytes(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.frombytes(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == 0x01:
            raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def get_status(self, status):
        status = status.upper()
        if status not in ["PROVIDER", "IPTEL", "VPN"]:
            raise ValueError("Status must be either PROVIDER, IPTEL or VPN")

        # Get index of entries for the status type
        payload = array("B")
        payload.frombytes(self.chunk_data(1, array("B", (0x01, 0xFC, 0x00)).tobytes()))
        payload.frombytes(
            self.chunk_data(
                1, (f"STAT_REQ={status}\r\nCOUNT=0\r\n\r\n").encode("ascii")
            )
        )
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv().decode("latin-1")
        if resp[15 : 33 + len(status)] != f"STAT_RESP={status}\r\nCOUNT=":
            raise RuntimeError("CommunicationError: Didn't receive status index")
        # The number of entries
        num_entries = int(resp[33 + len(status) : -4])
        entries = []
        for i in range(1, num_entries + 1):
            req_string = f"STAT_REQ={status}\r\nCOUNT={i:d}\r\n\r\n"
            payload = array("B")
            payload.frombytes(
                self.chunk_data(1, array("B", (0x01, 0xFC, 0x00)).tobytes())
            )
            payload.frombytes(self.chunk_data(1, req_string.encode("ascii")))
            packet = self.prepare_packet(
                (0xF0, 0x80), self.prepare_payload(payload.tobytes())
            )
            self.send(packet)
            resp = self.recv().decode("latin-1")
            if i < 10:
                end = 33 + len(status) + 1
            else:
                end = 33 + len(status) + len(str(i))
            if resp[15:end] != f"STAT_RESP={status}\r\nCOUNT={i:d}":
                raise RuntimeError(
                    "CommunicationError: Unexpected status response index"
                )
            tmp = {}
            for l in resp[end + 2 : -4].split("\r\n"):
                dtmp = l.split("=", 1)
                tmp[dtmp[0]] = dtmp[1]
            entries.append(tmp)
        return entries

    def print_providers(self):
        stat = self.get_status("PROVIDER")
        print(f"Number of entries: {len(stat):d}")
        print()
        print("{}\t\t\t{}".format("INDEX", "REQ_STRING"))
        for i in stat:
            print("{}\t{}\t{}".format(i["INDEX"], i["PROVIDER"], i["REG_STRING"]))

    def print_iptels(self):
        stat = self.get_status("IPTEL")
        print(f"Number of entries: {len(stat):d}")
        print()
        print(
            "{}\t\t{}\t{}\t{}\t{}".format("NAME", "MSN", "PORT", "IPSYSTEL", "REGISTER")
        )
        for i in stat:
            if len(i["NAME"]) < 8:
                i["NAME"] += "\t"
            i["IPSYSTEL"] += "\t"
            print(
                "{}\t{}\t{}\t{}\t{}".format(
                    i["NAME"], i["MSN"], i["PORT"], i["IPSYSTEL"], i["REGISTER"]
                )
            )

    def print_vpns(self):
        stat = self.get_status("VPN")
        print(f"Number of entries: {len(stat):d}")
        print()


class ICT_PhonebookComm(ICT_Comm):
    def login(self):
        payload = array("B", (0x01, 0x00, 0x05, 0x00, 0x01, 0x08))
        # Chunk index
        payload.append(0x01)
        payload.frombytes(struct.pack("!h", len(self.pbx_user) + 1))
        payload.frombytes(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.frombytes(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.frombytes(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == 0x01:
            raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def get_count_entries(self):
        payload = array("B", (0x03, 0x01, 0x1C, 0x00))
        payload.extend(array("B", (0x03, 0x33, 0x00, 0x00)))
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[11] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")
        return struct.unpack("!h", self.parse_packet(resp)[12:])[0]

    def set_count_entries(self, num):
        payload = array("B", (0x03, 0x01, 0x1D, 0x00))
        payload.extend(array("B", (0x05, 0x33, 0x00, 0x01)))
        payload = payload.tobytes() + struct.pack("!h", num)
        packet = self.prepare_packet((0xF0, 0x80), self.prepare_payload(payload))
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[8] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")

    def get_local_prefix(self):
        payload = array("B", (0x03, 0x01, 0x1C, 0x00))
        payload.extend(array("B", (0x05, 0x34, 0x00, 0x01, 0x00, 0x00)))
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[11] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")
        prefix_len, prefix = struct.unpack("!b10s", self.parse_packet(resp)[14:])
        prefix = prefix[0:prefix_len]
        return prefix.decode("latin-1")

    def set_local_prefix(self, num):
        payload = array("B", (0x03, 0x01, 0x1D, 0x00))
        payload.extend(array("B", (0x10, 0x34, 0x00, 0x01, 0x00, 0x00)))
        payload = payload.tobytes() + struct.pack(
            "!b10s", len(str(num).encode("latin-1")), str(num).encode("latin-1")
        )
        packet = self.prepare_packet((0xF0, 0x80), self.prepare_payload(payload))
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[8] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")

    def get_entry(self, id):
        payload = self.chunk_data(1, array("B", (0x01, 0x1C, 0x00)).tobytes())
        payload += self.chunk_data(
            1, array("B", (0x32, 0x00, 0x01)).tobytes() + struct.pack("!h", id)
        )
        self.send(self.prepare_packet((0xF0, 0x80), self.prepare_payload(payload)))
        resp = self.recv()
        payload = self.parse_packet(resp)
        (
            id,
            name_len,
            name,
            num_len,
            num,
            shortdial,
            bundle,
            callthrough,
            msn_len,
            msn,
        ) = struct.unpack("!hb20sb24shbbb4s", payload[12:])
        name = name[0:name_len].decode("latin-1")
        num = num[0:num_len].decode("latin-1")
        msn = msn[0:msn_len].decode("latin-1")
        return {
            "id": id,
            "name": name,
            "number": num,
            "bundle": bundle,
            "shortdial": shortdial,
            "msn": msn,
            "callthrough": callthrough,
        }

    def set_entry(
        self,
        id: int,
        name: str,
        num: str,
        shortdial: int = -1,
        bundle: int = -1,
        callthrough: int = 0,
        msn: str = "",
    ):
        name_data = name.encode("latin-1")[:20]
        num_data = num.encode("latin-1")[:24]
        msn_data = msn.encode("latin-1")[:4]
        payload = self.chunk_data(1, array("B", (0x01, 0x1D, 0x00)).tobytes())
        payload += self.chunk_data(
            1,
            array("B", (0x32, 0x00, 0x01)).tobytes()
            + struct.pack(
                "!hb20sb24shbbb4s18x",
                id,
                len(name_data),
                name_data,
                len(num_data),
                num_data,
                shortdial,
                bundle,
                callthrough,
                len(msn_data),
                msn_data,
            ),
        )
        self.send(self.prepare_packet((0xF0, 0x80), self.prepare_payload(payload)))
        resp = self.recv()
        if not self.parse_packet(resp)[8] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")

    def commit_phonebook(self):
        payload = array("B", (0x03, 0x01, 0x1D, 0x00))
        payload.extend(array("B", (0x03, 0x33, 0x01, 0x00)))
        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[8] == 0x01:
            raise RuntimeError("CommunicationError: Error executing query")


class ICT_ServiceComm(ICT_Comm):
    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array("B", (0x02, 0x02, 0x00)).tobytes():
            raise RuntimeError(
                "CommunicationError: Could not initiate handshake with PBX "
            )

        payload = array("B", (0x01, 0x00, 0x05, 0x00, 0x01, 0x03))
        # Chunk index
        payload.append(0x01)
        payload.frombytes(self.chunk_data(2, self.pbx_user + b"\x00"))
        # Chunk index
        payload.append(0x02)
        payload.frombytes(self.chunk_data(2, self.pbx_pass + b"\x00"))

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == 0x01:
            raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def pabx_info(self):
        payload = array(
            "B", (0x03, 0x01, 0xFE, 0x00, 0x05, 0x31, 0x2A, 0x39, 0x30, 0x0D)
        )

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)

        try:
            self.recv()
        except TimeoutError:
            raise RuntimeError(
                "CommunicationError: No data received from PBX. Did you log into the PBX in ServiceMode?"
            )
        self.recv()

    def read_diagnostics(self):
        payload = array("B", (0x03, 0x01, 0xFE))
        cmd = b"diag all"
        payload.frombytes(struct.pack("!h", len(cmd) + 1))
        payload.frombytes(cmd)
        # String terminator (\r)
        payload.append(0x0D)

        packet = self.prepare_packet(
            (0xF0, 0x80), self.prepare_payload(payload.tobytes())
        )
        self.send(packet)

        try:
            self.recv()
        except TimeoutError:
            raise RuntimeError(
                "CommunicationError: No data received from PBX. Did you log into the PBX in ServiceMode?"
            )
