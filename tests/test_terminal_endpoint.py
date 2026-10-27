"""Actual socket framing failures must terminate without inventing readiness."""
from pathlib import Path
import socket
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bench'))
if sys.platform=='linux':from terminal_endpoint import receive_marker


@unittest.skipUnless(sys.platform=='linux','Terminal probe requires Linux')
class TerminalMarkerFraming(unittest.TestCase):
    def test_partial_peer_close_is_rejected_instead_of_looping_on_eof(self):
        reader,writer=socket.socketpair()
        with reader:
            writer.sendall(b'{"ready":');writer.close()
            with self.assertRaisesRegex(RuntimeError,'closed before newline'):receive_marker(reader)

    def test_oversize_and_multiple_json_messages_are_rejected(self):
        for payload in (b'x'*4097,b'{}\n{}\n'):
            reader,writer=socket.socketpair()
            with reader,writer:
                writer.sendall(payload)
                with self.assertRaises((RuntimeError,ValueError)):receive_marker(reader)

    def test_complete_marker_preserves_integer_clock(self):
        reader,writer=socket.socketpair()
        with reader,writer:
            writer.sendall(b'{"ready_monotonic_ns":12345678901234567}\n')
            self.assertEqual(receive_marker(reader)['ready_monotonic_ns'],12345678901234567)


if __name__=='__main__':unittest.main()
