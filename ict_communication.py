#!/usr/bin/python -tt
#
# Basic functionality to interact with an Elmeg ICT PBX.
#
# Professional Configurator functionality is achieved by talking to port 5000
#

import socket, sys, struct, pprint
from array import array

class ICT_Comm():
    """The Elmeg ICT Communication class."""

    def __init__(self, host = "192.168.1.250", user = "Service", pwd = "Service"):
        """Initialize some data we need"""
        self.pbx_host = host
        self.pbx_port = 5000
        self.pbx_user = user
        self.pbx_pass = pwd
        self.__session = None
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

    def recv(self, buffersize = 4096):
        """Receive data. Has optional support for debugging prints."""
#        try:
        data = self.__session.recv(buffersize)
#        except socket.timeout:
#            raise RuntimeError('Timeout receiving data from PBX.')
        if self.debug == True:
            pprint.pprint(("rx", data))
        return data

    def prepare_packet(self, cmd, payload = None):
        """Prepare the package to be sent.
        (3) BCC Prefix
        (2) Total data length
        (1) Command data length
        (x) Command data
        (x) Payload
        """
        # Packet header - BCC fixed string
        header = (0x42, 0x43, 0x43)
        header = array('B', header)

        # Command instruction
        cmd = array('B', cmd)
        cmd_len = len(cmd)

        # Payload
        if payload is not None:
                payload_len = len(payload)
                payload_fmt = str(payload_len) + "s"
        else:
                payload_len = 0
                payload_fmt = "0s"
                payload = ""

        # total length
        total_len = cmd_len + 1 + payload_len

        # pack format string (Network byte order)
        fmt = "!" + "3s" + "h" + "b" + str(len(cmd)) + "s" + payload_fmt

        packet = struct.pack(fmt, header.tostring(), total_len, cmd_len, cmd.tostring(), payload)
        return packet

    def prepare_payload(self, payload):
        """Prepare the payload to be added to a package.
        (2) Total payload length
        (x) Payload
        """
        # Payload
        payload_len = len(payload)
        payload_fmt = str(payload_len) + "s"

        # total length
        total_len = payload_len

        # pack format string (Network byte order)
        fmt = "!" + "h" + payload_fmt

        packet = struct.pack(fmt, payload_len, payload)
        return packet

    def chunk_data(self, pack_length, data):
        """ Build chunks for elmeg communication """
        lengths = {
            1: 'B',
            2: 'H',
            4: 'L',
        }
        data_len = len(data)
        data_fmt = str(data_len) + "s"
        # pack format string (Network byte order)
        fmt = "!" + lengths[pack_length] + data_fmt
        return struct.pack(fmt, data_len, data)

    def dechunk_data(self, data):
        chunks = list()
        data_len = len(data)
        pos = 0
        while pos < data_len:
            chunk_len = struct.unpack("!b", data[pos])[0]
            chunks.append(data[pos + 1:pos + 1 + chunk_len])
            pos = pos + chunk_len + 1
        return chunks

    def parse_packet(self, data):
        if not data.startswith("BCC"):
                raise RuntimeError('ParseError: Prefix indicates not an Elmeg response packet')
        pckt_header = struct.unpack("!3shb", data[:6])

        # Subtract the prefix (3bytes) plus the length of the length field itself (2bytes) from the payload-length
        if not len(data) -5 == pckt_header[1]:
                raise RuntimeError('ParseError: Short packet detected')

        return data[6:]

    def init(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array('B', (0x02, 0x02, 0x00)).tostring():
                raise RuntimeError("CommunicationError: Could not initiate handshake with PBX ")

    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array('B', (0x02, 0x02, 0x00)).tostring():
                raise RuntimeError("CommunicationError: Could not initiate handshake with PBX ")

        payload = array('B', (0x01, 0x00, 0x05, 0x00, 0x01, 0x0b))
        # Chunk index
        payload.append(0x01)
        payload.fromstring(struct.pack("!h", len(self.pbx_user) + 1))
        payload.fromstring(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.fromstring(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.fromstring(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == chr(0x01):
                raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def logout(self):
        payload = array('B', (0x02, 0x01, 0x05, 0x00, 0x01, 0x0b))
        # Chunk index
        payload.append(0x01)
        payload.fromstring(struct.pack("!h", len(self.pbx_user) + 1))
        payload.fromstring(self.pbx_user)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == chr(0x01):
                raise RuntimeError("CommunicationError: Could not logout off PBX ")
        return True

    def pabx_ping(self):
        payload = array('B', (0x03, 0x01, 0x1b, 0x00, 0x00))

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        tmp = ""
        for c in self.parse_packet(resp)[9:]:
            if c != '\x00':
                tmp += c
            else:
                tmp += " "
        return tmp[:-1]

    def erase_lcr(self):
        file = "LCR.XML"
        payload = array('B', (0x03, 0x01, 0x25, 0x10, 0x00, 0x07, 0x01, 0x06, 0x05))
        payload.fromstring(struct.pack("!B", len(file)))
        payload.append(0x00)
        payload.fromstring(file)
        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)
        resp = self.recv()
        if self.parse_packet(resp) != array('B', (0xf0, 0x80, 0x00, 0x05, 0x03, 0x01, 0x25, 0x00, 0x00)).tostring():
            raise RuntimeError("CommunicationError: Unexpected data received")
        else:
            return True

    def get_lcr(self):
        file = "webpages/xml/lcr.xml"
        payload = array('B', (0x03, 0x01, 0x26, 0x00, 0x1a, 0x04, 0x07, 0x01, 0x06, 0x05))
        payload.fromstring(struct.pack("!B", len(file)))
        payload.fromstring(file)
        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)
        resp = self.recv()
        # Is the xml data following this packet?
        if self.parse_packet(resp) == array('B', (0xf0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x26, 0x00, 0x02, 0x00, 0x05)).tostring():
            xml_data = ""
            while True:
                try:
                    resp = self.recv()
                    data = self.parse_packet(resp)
                    # Get the sequence number
                    seq = struct.unpack("!B", data[11])[0]
                    # Get the xml_data
                    xml_data += data[12:]
                    # Ack the packet
                    payload = array('B', (0x03, 0x01, 0x28, 0x00, 0x03, 0x00, 0x00))
                    payload.fromstring(struct.pack("!B", seq))
                    packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
                    self.send(packet)
                    # This might be an end of transmission marker
                    # 0x05 first packet, 0x04 further data, 0x06 end of data
                    if data[9] == chr(0x06):
                        break
                except socket.timeout:
                    break
        elif self.parse_packet(resp) == array('B', (0xf0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x26, 0x00, 0x02, 0x51, 0x00)).tostring():
            # print "No LCR data available on the PBX"
            return False
        else:
            raise RuntimeError("CommunicationError: Unexpected data received")
        return xml_data

    def put_lcr(self, xml_data):
        file = "LCR.XML"
        payload = array('B', (0x03, 0x01, 0x27, 0x00, 0x0e, 0x04, 0x07, 0x01, 0x06, 0x05))
        payload.fromstring(struct.pack("!B", len(file)))
        payload.fromstring(file)
        payload.append(0x00)
        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)
        resp = self.recv()
        # Is the PBX ready for upload?
        if self.parse_packet(resp) == array('B', (0xf0, 0x80, 0x00, 0x07, 0x03, 0x01, 0x27, 0x00, 0x02, 0x00, 0x05)).tostring():
            seq = 0
            while len(xml_data) > 0:
                # Get data to transmit in nice 512byte chunks
                tx = xml_data[:512]
                xml_data = xml_data[512:]
                try:
                    payload = array('B', (0x03, 0x01, 0x29))
                    payload.fromstring(struct.pack("!h", len(tx) + 3))
                    if len(xml_data) == 0:
                        payload.append(0x06)
                    elif seq == 0:
                        payload.append(0x05)
                    else:
                        payload.append(0x04)
                    payload.append(0x00)
                    payload.fromstring(struct.pack("!B", seq))
                    payload.fromstring(tx)
                    packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
                    self.send(packet)
                    # Check for ack
                    resp = self.recv()
                    if self.parse_packet(resp) == array('B', (0xf0, 0x80, 0x00, 0x08, 0x03, 0x01, 0x29, 0x00, 0x03, 0x00, 0x00)).tostring() + chr(seq):
                        seq += 1
                    elif self.parse_packet(resp) == array('B', (0xf0, 0x80, 0x00, 0x08, 0x03, 0x01, 0x29, 0x00, 0x03, 0x03, 0x00)).tostring() + chr(seq):
                        # print "Cannot write LCR data, LCR data already present."
                        return False
                    else:
                        raise RuntimeError("CommunicationError: Unexpected data received")
                except socket.timeout:
                    # print "timeout"
                    break
        else:
            raise RuntimeError("CommunicationError: Unexpected data received")
        return True


class ICT_StatusComm(ICT_Comm):

    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array('B', (0x02, 0x02, 0x00)).tostring():
                raise RuntimeError("CommunicationError: Could not initiate handshake with PBX ")

        payload = array('B', (0x01, 0x00, 0x05, 0x00, 0x01, 0x01))
        # Chunk index
        payload.append(0x01)
        payload.fromstring(struct.pack("!h", len(self.pbx_user) + 1))
        payload.fromstring(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.fromstring(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.fromstring(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == chr(0x01):
                raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def get_status(self, status):
        status = status.upper()
        if status not in ['PROVIDER', 'IPTEL', 'VPN']:
            raise ValueError('Status must be either PROVIDER, IPTEL or VPN')

        # Get index of entries for the status type
        payload = array('B')
        payload.fromstring(self.chunk_data(1, array('B', (0x01, 0xfc, 0x00)).tostring()))
        payload.fromstring(self.chunk_data(1, 'STAT_REQ=%s\r\nCOUNT=0\r\n\r\n' % (status)))
        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)
        resp = self.recv()
        if resp[15:33 + len(status)] != 'STAT_RESP=%s\r\nCOUNT=' % (status):
            raise RuntimeError("CommunicationError: Didn't receive status index")
        # The number of entries
        num_entries = int(resp[33 + len(status):-4])
        entries = list()
        for i in range(1, num_entries + 1):
            req_string = 'STAT_REQ=%s\r\nCOUNT=%i\r\n\r\n' % (status, i)
            payload = array('B')
            payload.fromstring(self.chunk_data(1, array('B', (0x01, 0xfc, 0x00)).tostring()))
            payload.fromstring(self.chunk_data(1, req_string))
            packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
            self.send(packet)
            resp = self.recv()
            if i < 10:
                end = 33 + len(status) + 1
            else:
                end = 33 + len(status) + 2
            if resp[15:end] != 'STAT_RESP=%s\r\nCOUNT=%i' % (status, i):
                raise RuntimeError("CommunicationError: Unexpected status response index")
            tmp = dict()
            for l in resp[end+2:-4].split('\r\n'):
                dtmp = l.split('=')
                tmp[dtmp[0]] = dtmp[1]
            entries.append(tmp)
        return entries

    def print_providers(self):
        stat = self.get_status('PROVIDER')
        print "Number of entries: %i" % (len(stat))
        print
        print '%s\t\t\t%s' % ('INDEX', 'REQ_STRING')
        for i in stat:
            print '%s\t%s\t%s' % (i['INDEX'], i['PROVIDER'], i['REG_STRING'])

    def print_iptels(self):
        stat = self.get_status('IPTEL')
        print "Number of entries: %i" % (len(stat))
        print
        print '%s\t\t%s\t%s\t%s\t%s' % ('NAME', 'MSN', 'PORT', 'IPSYSTEL', 'REGISTER')
        for i in stat:
            if len(i['NAME']) < 8:
                i['NAME'] += '\t'
            i['IPSYSTEL'] += '\t'
            print '%s\t%s\t%s\t%s\t%s' % (i['NAME'], i['MSN'], i['PORT'], i['IPSYSTEL'], i['REGISTER'])

    def print_vpns(self):
        stat = self.get_status('VPN')
        print "Number of entries: %i" % (len(stat))
        print
#        print '%s\t\t%s\t%s\t%s\t%s' % ('NAME', 'MSN', 'PORT', 'IPSYSTEL', 'REGISTER')
#        for i in stat:
#            if len(i['NAME']) < 8:
#                i['NAME'] += '\t'
#            i['IPSYSTEL'] += '\t'
#            print '%s\t%s\t%s\t%s\t%s' % (i['NAME'], i['MSN'], i['PORT'], i['IPSYSTEL'], i['REGISTER'])


class ICT_PhonebookComm(ICT_Comm):

    def login(self):
        payload = array('B', (0x01, 0x00, 0x05, 0x00, 0x01, 0x08))
        # Chunk index
        payload.append(0x01)
        payload.fromstring(struct.pack("!h", len(self.pbx_user) + 1))
        payload.fromstring(self.pbx_user)
        # String terminator
        payload.append(0x00)
        # Chunk index
        payload.append(0x02)
        payload.fromstring(struct.pack("!h", len(self.pbx_pass) + 1))
        payload.fromstring(self.pbx_pass)
        # String terminator
        payload.append(0x00)

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == chr(0x01):
                raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def get_count_entries(self):
        payload = array('B',(0x03, 0x01, 0x1c, 0x00))
        payload.extend(array('B',(0x03, 0x33, 0x00, 0x00)))
        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[11] == chr(0x01):
            raise RuntimeError("CommunicationError: Error executing query")
        return struct.unpack('!h', self.parse_packet(resp)[12:])[0]
        
    def get_entry(self, id):
        payload = self.chunk_data(1, array('B',(0x01, 0x1c, 0x00)).tostring())
        payload += self.chunk_data(1, array('B',(0x32, 0x00, 0x01)).tostring() + struct.pack("!h", id))
        self.send(self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload)))
        resp = self.recv()
        payload = self.parse_packet(resp)
        id, name_len, name, num_len, num, shortdial, bundle, callthrough, msn_len, msn = struct.unpack("!12xhb20sb24sxbbbb4s", payload)
        name = name[0:name_len]
        num = num[0:num_len]
        msn = msn[0:msn_len]
        return {"id": id, "name": name, "number": num, "bundle": bundle, "shortdial": shortdial, "msn": msn, "callthrough": callthrough}

    def set_entry(self, id, name, number, shortdial=-1, bundle=-1, callthrough=0, msn=''):
        pass

class ICT_ServiceComm(ICT_Comm):

    def login(self):
        packet = self.prepare_packet((0x01, 0x80, 0x00), None)
        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp) == array('B', (0x02, 0x02, 0x00)).tostring():
                raise RuntimeError("CommunicationError: Could not initiate handshake with PBX ")

        payload = array('B', (0x01, 0x00, 0x05, 0x00, 0x01, 0x03))
        # Chunk index
        payload.append(0x01)
        payload.fromstring(self.chunk_data(2, self.pbx_user % (status)))
        # Chunk index
        payload.append(0x02)
        payload.fromstring(self.chunk_data(2, self.pbx_user % (status)))

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))

        self.send(packet)
        resp = self.recv()
        if not self.parse_packet(resp)[5] == chr(0x01):
                raise RuntimeError("CommunicationError: Could not login to PBX ")
        return True

    def pabx_info(self):
        payload = array('B', (0x03, 0x01, 0xfe, 0x00, 0x05, 0x31, 0x2a, 0x39, 0x30, 0x0d))

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)

        try:
            resp = self.recv()
        except socket.timeout:
            raise RuntimeError("CommunicationError: No data received from PBX. Did you log into the PBX in ServiceMode?")
        resp = self.recv()

    def read_diagnostics(self):
        payload = array('B', (0x03, 0x01, 0xfe))
        cmd = "diag all"
        payload.fromstring(struct.pack("!h", len(cmd) + 1))
        payload.fromstring(cmd)
        # String terminator (\r)
        payload.append(0x0d)

        packet = self.prepare_packet((0xf0, 0x80), self.prepare_payload(payload.tostring()))
        self.send(packet)

        try:
            resp = self.recv()
        except socket.timeout:
            raise RuntimeError("CommunicationError: No data received from PBX. Did you log into the PBX in ServiceMode?")



if __name__ == '__main__':
    pbx = '192.168.2.250'
    ict = ICT_PhonebookComm(pbx)
    ict.debug = False
    ict.connect()
    ict.init()
    ict.login()
    for i in range(0, ict.get_count_entries()):
        print ict.get_entry(i)
    ict.logout()
    ict.disconnect()
