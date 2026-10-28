"""Protocol success, rejection, timeout, and command-line behavior."""

import socket
import struct
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_migration import packet

from ict_utils import controlcenter, lcr, phonebook
from ict_utils import ict_communication as comm


@pytest.fixture
def ict(monkeypatch):
    device = comm.ICT_PhonebookComm()
    monkeypatch.setattr(device, "send", Mock())
    monkeypatch.setattr(device, "recv", Mock())
    return device


@pytest.mark.parametrize(
    "width,expected", [(1, b"\x03"), (2, b"\x00\x03"), (4, b"\x00\x00\x00\x03")]
)
def test_chunk_length_widths(width, expected):
    assert comm.ICT_Comm().chunk_data(width, b"abc") == expected + b"abc"


@pytest.mark.parametrize(
    "cls",
    [comm.ICT_Comm, comm.ICT_StatusComm, comm.ICT_PhonebookComm, comm.ICT_ServiceComm],
)
def test_login_rejected(cls, monkeypatch):
    device = cls()
    responses = [packet(b"\x02\x02\x00"), packet(b"\x00" * 6)]
    if cls is comm.ICT_PhonebookComm:
        responses.pop(0)
    monkeypatch.setattr(device, "send", Mock())
    monkeypatch.setattr(device, "recv", Mock(side_effect=responses))
    with pytest.raises(RuntimeError, match="Could not login"):
        device.login()


@pytest.mark.parametrize(
    "cls", [comm.ICT_Comm, comm.ICT_StatusComm, comm.ICT_ServiceComm]
)
def test_handshake_rejected(cls, monkeypatch):
    device = cls()
    monkeypatch.setattr(device, "send", Mock())
    monkeypatch.setattr(device, "recv", Mock(return_value=packet(b"bad")))
    with pytest.raises(RuntimeError, match="handshake"):
        device.login()


def test_logout_rejected(ict):
    ict.recv.return_value = packet(b"\x00" * 6)
    with pytest.raises(RuntimeError, match="logout"):
        ict.logout()


@pytest.mark.parametrize(
    "method,args,index",
    [
        ("get_count_entries", (), 11),
        ("get_local_prefix", (), 11),
        ("set_count_entries", (3,), 8),
        ("set_local_prefix", ("030",), 8),
        ("set_entry", (0, "Name", "0123"), 8),
        ("commit_phonebook", (), 8),
    ],
)
def test_phonebook_query_rejected(ict, method, args, index):
    ict.recv.return_value = packet(bytes(index + 1))
    with pytest.raises(RuntimeError, match="Error executing query"):
        getattr(ict, method)(*args)


@pytest.mark.parametrize("count", [0, 1, 999])
def test_phonebook_count(ict, count):
    ict.recv.return_value = packet(bytes(11) + b"\x01" + struct.pack("!h", count))
    assert ict.get_count_entries() == count
    ict.recv.return_value = packet(bytes(8) + b"\x01")
    ict.set_count_entries(count)
    assert ict.send.call_args.args[0].endswith(struct.pack("!h", count))


@pytest.mark.parametrize("prefix", ["", "0", "030", "0123456789"])
def test_phonebook_prefix(ict, prefix):
    ict.recv.return_value = packet(
        bytes(11)
        + b"\x01\x00\x00"
        + struct.pack("!b10s", len(prefix), prefix.encode("ascii"))
    )
    assert ict.get_local_prefix() == prefix
    ict.recv.return_value = packet(bytes(8) + b"\x01")
    ict.set_local_prefix(prefix)
    assert ict.send.call_args.args[0].endswith(
        struct.pack("!b10s", len(prefix), prefix.encode("ascii"))
    )


@pytest.mark.parametrize("status", ["PROVIDER", "IPTEL", "VPN"])
@pytest.mark.parametrize("count", [0, 1, 10, 100])
def test_status_entries(status, count, monkeypatch):
    device = comm.ICT_StatusComm()

    def response(text):
        return packet(bytes(9) + text.encode("latin-1") + b"\r\n\r\n")

    responses = [response(f"STAT_RESP={status}\r\nCOUNT={count}")]
    responses.extend(
        response(
            f"STAT_RESP={status}\r\nCOUNT={i}\r\nINDEX={i}\r\nNAME=Jörg\r\nVALUE=a=b"
        )
        for i in range(1, count + 1)
    )
    monkeypatch.setattr(device, "recv", Mock(side_effect=responses))
    send = Mock()
    monkeypatch.setattr(device, "send", send)
    entries = device.get_status(status.lower())
    assert len(entries) == count
    assert send.call_count == count + 1
    if entries:
        assert entries[-1] == {"INDEX": str(count), "NAME": "Jörg", "VALUE": "a=b"}


def test_invalid_status(ict):
    with pytest.raises(ValueError, match="Status must"):
        comm.ICT_StatusComm().get_status("unknown")


@pytest.mark.parametrize("method", ["get_lcr", "put_lcr", "erase_lcr"])
def test_lcr_unexpected_response(ict, method):
    ict.recv.return_value = packet(b"bad")
    args = (b"<xml/>",) if method == "put_lcr" else ()
    with pytest.raises(RuntimeError, match="Unexpected data"):
        getattr(ict, method)(*args)


def test_lcr_missing_and_erase(ict):
    ict.recv.return_value = packet(b"\xf0\x80\x00\x07\x03\x01\x26\x00\x02\x51\x00")
    assert ict.get_lcr() is False
    ict.recv.return_value = packet(b"\xf0\x80\x00\x05\x03\x01\x25\x00\x00")
    assert ict.erase_lcr() is True


@pytest.mark.parametrize(
    "reply",
    [
        TimeoutError(),
        packet(b"\xf0\x80\x00\x08\x03\x01\x29\x00\x03\x03\x00\x00"),
        packet(b"bad"),
    ],
)
def test_lcr_upload_failure(ict, reply):
    ict.recv.side_effect = [
        packet(b"\xf0\x80\x00\x07\x03\x01\x27\x00\x02\x00\x05"),
        reply,
    ]
    if isinstance(reply, TimeoutError):
        with pytest.raises(RuntimeError, match="Incomplete LCR upload"):
            ict.put_lcr(b"<xml/>")
    elif reply == packet(b"bad"):
        with pytest.raises(RuntimeError, match="Unexpected data"):
            ict.put_lcr(b"<xml/>")
    else:
        assert ict.put_lcr(b"<xml/>") is False


@pytest.mark.parametrize(
    "module,action",
    [
        (phonebook, "print"),
        (phonebook, "erase"),
        (phonebook, "upload"),
        (phonebook, "download"),
        (lcr, "erase"),
        (lcr, "upload"),
        (lcr, "download"),
    ],
)
def test_cli_actions(module, action, monkeypatch):
    args = ["command", "-u", "User", "-p", "Password", action.upper()]
    if action in ("upload", "download"):
        args.append("file")
    monkeypatch.setattr(sys, "argv", args)
    opts, parsed, filename = module.parse_cmdline()
    assert (opts.user, opts.password, parsed) == ("User", "Password", action)
    assert filename == ("file" if action in ("upload", "download") else None)


@pytest.mark.parametrize("module", [phonebook, lcr])
@pytest.mark.parametrize(
    "args",
    [
        [],
        ["unknown"],
        ["upload"],
        ["download"],
        ["erase", "extra"],
        ["upload", "one", "two"],
    ],
)
def test_cli_invalid_arguments(module, args, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["command", *args])
    with pytest.raises(SystemExit) as error:
        module.parse_cmdline()
    assert error.value.code == 2


@pytest.mark.parametrize(
    "action,helper",
    [
        ("print", "pretty_print"),
        ("erase", "erase"),
        ("upload", "csv_import"),
        ("download", "csv_export"),
    ],
)
def test_phonebook_cli_dispatch(action, helper, monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "phonebook",
            "-u",
            "User",
            "-p",
            "Password",
            action,
            *(["file"] if action in ("upload", "download") else []),
        ],
    )
    factory = Mock()
    monkeypatch.setattr(comm, "ICT_PhonebookComm", factory)
    operation = Mock()
    monkeypatch.setattr(phonebook, helper, operation)
    phonebook.main()
    factory.assert_called_once_with("192.168.1.250", "User", "Password")
    operation.assert_called_once()
    factory.return_value.logout.assert_called_once()
    factory.return_value.disconnect.assert_called_once()


def test_csv_invalid_row_does_not_change_pbx(tmp_path):
    path = tmp_path / "invalid.csv"
    path.write_text(
        "name,number,shortdial,bundle,callthrough,msn\nName,123,invalid,-1,0,\n",
        encoding="utf-8",
    )
    device = Mock()
    with pytest.raises(ValueError):
        phonebook.csv_import(device, path, "030")
    assert device.mock_calls == []


def test_csv_empty_and_sorted(tmp_path):
    path = tmp_path / "phonebook.csv"
    header = "name,number,shortdial,bundle,callthrough,msn\n"
    path.write_text(header, encoding="utf-8")
    device = Mock()
    phonebook.csv_import(device, path, "030")
    device.set_count_entries.assert_called_once_with(0)
    device.set_entry.assert_not_called()
    path.write_text(header + "Zed,2,-1,-1,0,\nanna,1,0,0,1,2\n", encoding="utf-8")
    device.reset_mock()
    phonebook.csv_import(device, path, "030")
    assert [call.args[1] for call in device.set_entry.call_args_list] == ["anna", "Zed"]


def test_lcr_file_failures_preserve_destination(tmp_path):
    path = tmp_path / "lcr.xml"
    path.write_bytes(b"existing")
    device = Mock()
    device.get_lcr.return_value = False
    with pytest.raises(RuntimeError, match="No LCR table"):
        lcr.download(device, path)
    assert path.read_bytes() == b"existing"
    device.put_lcr.return_value = False
    with pytest.raises(RuntimeError, match="refused"):
        lcr.upload(device, path)


@pytest.mark.parametrize("action", ["up", "DOWN", "hangup", "DIAL", "invalid"])
def test_wan_actions(action, monkeypatch):
    device = controlcenter.ICT_CC()
    send = Mock()
    monkeypatch.setattr(device, "send", send)
    result = device.ifconfig(action)
    if action == "invalid":
        assert result is False
        send.assert_not_called()
    else:
        send.assert_called_once_with(f"WANLINK\r\nACTION={action.upper()}\r\n\r\n")


def test_discovery_receives_responses(monkeypatch):
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    session.recvfrom.side_effect = [
        (b"detect router in lan by elmeg", ("192.0.2.1", 5000)),
        (b"elmeg router received", ("192.0.2.2", 5000)),
        TimeoutError(),
        (b"unrelated", ("192.0.2.3", 5000)),
        TimeoutError(),
    ]
    monkeypatch.setattr(controlcenter.socket, "socket", Mock(return_value=session))
    monkeypatch.setattr(
        controlcenter.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [SimpleNamespace(family=socket.AF_INET, broadcast="192.0.2.255")],
            "lo": [SimpleNamespace(family=socket.AF_INET, broadcast=None)],
        },
    )
    assert controlcenter.ICT_CC().discover_pbx() == (
        False,
        [["192.0.2.2", "elmeg router received"]],
    )
    session.sendto.assert_called_once_with(
        b"detect router in lan by elmeg", ("192.0.2.255", 5000)
    )


def test_controlcenter_socket_bytes(monkeypatch):
    session = Mock()
    factory = Mock(return_value=session)
    monkeypatch.setattr(controlcenter.socket, "create_connection", factory)
    device = controlcenter.ICT_CC()
    device.connect()
    device.send("WANLINK\r\n")
    session.sendall.assert_called_once_with(b"WANLINK\r\n")
    session.recv.return_value = b"J\xf6rg"
    assert device.recv(4096) == "Jörg"
    session.recv.return_value = b""
    with pytest.raises(ConnectionError):
        device.recv(4096)
    device.disconnect()
    session.close.assert_called_once()
