'''Classes implementing connections to VRT sockets.'''
import socket
import threading
import select
from collections import defaultdict, deque
from typing import Union, Iterable, List, Dict
from .constants import VTI_STREAM_GREETING, VrtPacketType
from .packet import VtiVrtPacket, _recvn

class VtiVrtReader():
    '''Represents a connection to a VRT streamer socket.

:ivar binary_point: If not None, for any data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
:ivar sock: The connected socket.
:ivar buffered_context: A dict buffering context packets during calls to `read_collate_context`.
'''
    def __init__(self, host : str, port : int = 9900, binary_point : int = None):
        '''
:param host: The hostname or IP address of the server to connect to.
:param port: The TCP port to connect to.
:param binary_point: If specified, and if the packet is a data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
'''
        self.binary_point = binary_point
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('', 0))
        self.sock.connect((host, port))
        self.sock.settimeout(5)
        greet = _recvn(self.sock, len(VTI_STREAM_GREETING))
        if greet != VTI_STREAM_GREETING:
            raise IOError(f'Invalid stream greeting: "{greet}" != "{VTI_STREAM_GREETING}"')
        self.sock.settimeout(None)
        self.buffered_context = defaultdict(list)

    def fileno(self) -> int:
        '''Returns the file descriptor of the connected socket.'''
        return self.sock.fileno()

    def read_one_packet(self) -> VtiVrtPacket:
        '''Reads one VRT packet from the socket.'''
        return VtiVrtPacket.from_socket(self.sock, self.binary_point)

    def read_collate_context(self) -> VtiVrtPacket:
        '''Reads VRT packets from the socket until a data packet is received.

Any context packets received are saved in the :py:attr:`buffered_context` attribute. When a data packet is received, any context packets in :py:attr:`buffered_context` whose :py:attr:`stream_id` attribute matches that of the data packet will be removed from :py:attr:`buffered_context` and added to the packet's :py:attr:`context` list.
        '''
        while True:
            packet = self.read_one_packet()
            if packet.packet_type in (VrtPacketType.IF_CONTEXT, VrtPacketType.EXT_CONTEXT):
                self.buffered_context[packet.stream_id].append(packet)
            else:
                packet.context = self.buffered_context[packet.stream_id]
                self.buffered_context[packet.stream_id] = []
                return packet

    def read(self, collate_context : bool = False) -> VtiVrtPacket:
        '''Read a VRT packet from the socket.

:param collate_context: If true, only return once a data packet has been received, and attach any context packets matching its `stream_id` to it. If false, return the first packet received, regardless of its type.
'''
        if collate_context:
            return self.read_collate_context()
        return self.read_one_packet()

class VtiVrtThread(threading.Thread):
    '''Reads VRT packets from a collection of sockets, and collates them by stream id.'''
    def __init__(self, args : Iterable):
        '''
:param args: The parameters for a connecting to a collection of VRT sockets. Each entry should be a tuple containing the  arguments to the constructor of :py:class:`VtiVrtReader` (hostname, port, binary_point); note that port and binary_point are optional.
'''
        self.readers = []
        for vals in args:
            self.readers.append(VtiVrtReader(*vals))
        threading.Thread.__init__(self)
        self.packets = defaultdict(deque)
        self.new_data = threading.Condition()
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            readers, _, _ = select.select(self.readers, [], [], 1.0)
            for reader in readers:
                packet = reader.read_collate_context()
                with self.new_data:
                    self.packets[packet.stream_id].append(packet)
                    self.new_data.notify_all()

    def stop(self):
        '''Stop the thread.'''
        self.running = False

    def num_packets(self, stream_ids : Iterable[int] = None):
        '''Gets the minimum number of available packets among all specified stream_ids.

:param stream_ids: The stream_ids to get packets from. If unspecified, all known stream_ids will be queried.
'''
        if stream_ids is None:
            stream_ids = self.packets.keys()
        try:
            return min(map(len, map(self.packets.get, stream_ids))) or 0
        except ValueError:
            return 0

    def read(self, num : int = None, stream_ids : Union[Iterable[int],Dict[int,str]] = None, block : bool = False, timeout : float = None) -> Union[Dict[int, List[VtiVrtPacket]], Dict[str, List[VtiVrtPacket]]]:
        '''Read packets from all specified stream_ids.

:param num: The number of packets to get for each stream_id. If None or not positive, the minimum available among all specified stream_ids will be used. If that is 0, 1 will be used.
:param stream_ids: The stream_ids to get packets from. If unspecified, packets will be returned from all known stream_ids. This may be a collection of stream id integers, or a dict mapping stream ids to channel names.
:param block: Whether to block if packets are missing from any specified stream_ids. If false, all available data will be returned immediately, and timeout will be ignored.
:param timeout: The maximum amount of seconds to wait for packets, if block is true.

:returns: A dictionary mapping streams ids (or their associated channel names, if stream_ids was a dict) to lists of packets.

:raises TimeoutError: If `block` is true and `timeout` is exceeded.
        '''
        packets = defaultdict(list)
        if stream_ids is None:
            stream_ids = self.packets.keys()
        if num is None or num < 1:
            num = self.num_packets(stream_ids) or 1

        def all_data_available():
            for sid in stream_ids:
                if len(self.packets[sid]) < num:
                    return False
            return bool(stream_ids)

        if block:
            with self.new_data:
                if not all_data_available():
                    if not self.new_data.wait_for(all_data_available, timeout):
                        raise TimeoutError('Timed Out waiting for VRT packets')

        for _ in range(num):
            for sid in stream_ids:
                if isinstance(stream_ids, dict):
                    key = stream_ids[sid]
                else:
                    key = sid
                packets[key].append(self.packets[sid].popleft())
        return packets
