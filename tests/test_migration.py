"""Hardware-free checks for the Python 3 migration."""

import contextlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ict_utils import controlcenter, lcr, phonebook
from ict_utils import ict_communication as comm


def packet(payload: bytes) -> bytes:
    return b"BCC" + struct.pack("!hB", len(payload) + 1, 2) + payload


class MigrationTests(unittest.TestCase):
    def test_packets_and_chunks(self):
        ict = comm.ICT_Comm()
        self.assertEqual(
            ict.prepare_packet((1, 128, 0)), b"BCC\x00\x04\x03\x01\x80\x00"
        )
        self.assertEqual(ict.prepare_payload(b"abc"), b"\x00\x03abc")
        data = bytes(range(200))
        self.assertEqual(ict.dechunk_data(ict.chunk_data(1, data)), [data])
        with self.assertRaises(ValueError):
            ict.dechunk_data(b"\x03ab")
        for malformed in (b"BCC", b"XXX\x00\x01\x00", b"BCC\x00\x05\x00"):
            with self.assertRaises(RuntimeError):
                ict.parse_packet(malformed)

    def test_tcp_fragmentation_and_multiple_packets(self):
        ict = comm.ICT_Comm()
        incoming = bytearray(packet(b"first") + packet(b"second"))

        def receive(size):
            size = min(size, 2)
            result = bytes(incoming[:size])
            del incoming[:size]
            return result

        with patch.object(comm.socket, "socket") as factory:
            factory.return_value.recv.side_effect = receive
            ict.connect()
            self.assertEqual(ict.parse_packet(ict.recv()), b"first")
            self.assertEqual(ict.parse_packet(ict.recv()), b"second")
            ict.send(b"test")
            factory.return_value.sendall.assert_called_once_with(b"test")
            with self.assertRaises(ConnectionError):
                ict.recv()
            ict.disconnect()

    def test_login_variants_and_logout(self):
        for cls in (
            comm.ICT_Comm,
            comm.ICT_StatusComm,
            comm.ICT_PhonebookComm,
            comm.ICT_ServiceComm,
        ):
            ict = cls(user="Jörg", pwd="secret")
            responses = [packet(b"\x02\x02\x00"), packet(b"\x00" * 5 + b"\x01")]
            if cls is comm.ICT_PhonebookComm:
                responses.pop(0)
            with (
                patch.object(ict, "recv", side_effect=responses),
                patch.object(ict, "send") as send,
            ):
                self.assertTrue(ict.login())
                sent = send.call_args.args[0]
                self.assertIn(b"J\xf6rg\x00", sent)
                self.assertIn(b"secret\x00", sent)
            with (
                patch.object(ict, "recv", return_value=packet(b"\x00" * 5 + b"\x01")),
                patch.object(ict, "send"),
            ):
                self.assertTrue(ict.logout())

    def test_phonebook_entry_round_trip(self):
        ict = comm.ICT_PhonebookComm()
        with (
            patch.object(ict, "recv", return_value=packet(b"\x00" * 8 + b"\x01")),
            patch.object(ict, "send") as send,
        ):
            ict.set_entry(7, "Jörg" * 8, "0123", 42, -1, 1, "99")
            chunks = ict.dechunk_data(ict.parse_packet(send.call_args.args[0])[4:])
            record = chunks[1][3:-18]
        with (
            patch.object(ict, "recv", return_value=packet(b"\x00" * 12 + record)),
            patch.object(ict, "send"),
        ):
            entry = ict.get_entry(7)
        self.assertEqual(entry["name"], ("Jörg" * 8)[:20])
        self.assertEqual(entry["number"], "0123")
        self.assertEqual(entry["shortdial"], 42)
        self.assertEqual(entry["bundle"], -1)
        self.assertEqual(entry["msn"], "99")

    def test_lcr_download_and_upload(self):
        ict = comm.ICT_Comm()
        xml = b"<xml>\xff</xml>"
        ready = b"\xf0\x80\x00\x07\x03\x01\x26\x00\x02\x00\x05"
        final = b"\x00" * 9 + b"\x06\x00\x00" + xml
        with (
            patch.object(ict, "recv", side_effect=[packet(ready), packet(final)]),
            patch.object(ict, "send"),
        ):
            self.assertEqual(ict.get_lcr(), xml)
        with (
            patch.object(ict, "recv", side_effect=[packet(ready), TimeoutError()]),
            patch.object(ict, "send"),
            self.assertRaises(RuntimeError),
        ):
            ict.get_lcr()
        upload_ready = ready[:6] + b"\x27" + ready[7:]
        ack = b"\xf0\x80\x00\x08\x03\x01\x29\x00\x03\x00\x00"
        xml = bytes(range(256)) * 3
        with (
            patch.object(
                ict,
                "recv",
                side_effect=[
                    packet(upload_ready),
                    packet(ack + b"\x00"),
                    packet(ack + b"\x01"),
                ],
            ),
            patch.object(ict, "send") as send,
        ):
            self.assertTrue(ict.put_lcr(xml))
            packets = [
                ict.parse_packet(call.args[0]) for call in send.call_args_list[1:]
            ]
            self.assertEqual(packets[0][9], 5)
            self.assertEqual(packets[1][9], 6)
            self.assertEqual(b"".join(data[12:] for data in packets), xml)

    def test_csv_and_binary_files(self):
        ict = Mock()
        ict.get_count_entries.return_value = 1
        ict.get_entry.return_value = {
            "name": "Jörg, Test",
            "number": "0123",
            "shortdial": -1,
            "bundle": -1,
            "callthrough": 0,
            "msn": "",
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            csv_path = Path(directory) / "phonebook.csv"
            phonebook.csv_export(ict, csv_path)
            phonebook.csv_import(ict, csv_path, "030")
            ict.set_count_entries.assert_called_once_with(1)
            ict.set_entry.assert_called_once_with(
                0, "Jörg, Test", "0123", -1, -1, 0, ""
            )
            xml_path = Path(directory) / "lcr.xml"
            ict.get_lcr.return_value = b"<xml>\xff</xml>"
            lcr.download(ict, xml_path)
            lcr.upload(ict, xml_path)
            ict.put_lcr.assert_called_once_with(b"<xml>\xff</xml>")

    def test_controlcenter_and_syslog(self):
        ict = controlcenter.ICT_CC()
        with (
            patch.object(ict, "send") as send,
            patch.object(
                ict, "recv", side_effect=["WANLINK=UP\r\nPROVIDER=a=b\r\n", "\r\n"]
            ),
        ):
            self.assertEqual(ict.status(), {"WANLINK": "UP", "PROVIDER": "a=b"})
            send.assert_called_once_with("STAT_REQ\r\n\r\n")
        logger = controlcenter.ICT_Syslog()
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            patch.object(
                logger,
                "recv",
                side_effect=[
                    "fir",
                    TimeoutError(),
                    "st\nsec",
                    "ond\n",
                    ConnectionError(),
                ],
            ),
            self.assertRaises(ConnectionError),
        ):
            logger.read()
        self.assertEqual(output.getvalue(), "first\nsecond\n")


if __name__ == "__main__":
    unittest.main()
