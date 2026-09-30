import json
import socket
import struct
import threading

from sentinel import zabbix_sender


def test_packet_format():
    pkt = zabbix_sender.build_packet("nas", {"sentinel.status": 2})
    assert pkt.startswith(b"ZBXD\x01")
    length = struct.unpack("<I", pkt[5:9])[0]
    body = json.loads(pkt[13:])
    assert length == len(pkt) - 13
    assert body["data"][0] == {"host": "nas", "key": "sentinel.status", "value": "2"}


def test_send_against_fake_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = {}

    def serve():
        conn, _ = srv.accept()
        hdr = conn.recv(13)
        n = struct.unpack("<I", hdr[5:9])[0]
        data = b""
        while len(data) < n:
            data += conn.recv(n - len(data))
        received.update(json.loads(data))
        resp = json.dumps({"response": "success", "info": "processed: 1; failed: 0"}).encode()
        conn.sendall(b"ZBXD\x01" + struct.pack("<II", len(resp), 0) + resp)
        conn.close()

    t = threading.Thread(target=serve)
    t.start()
    resp = zabbix_sender.send("127.0.0.1", port, "nas", {"sentinel.score": 90})
    t.join()
    srv.close()
    assert resp["response"] == "success"
    assert received["data"][0]["key"] == "sentinel.score"
