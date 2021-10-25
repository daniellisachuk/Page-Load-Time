#!/usr/bin/env python3
'''
version 3 Page Load Time Algorithm Container Implementations
'''


class PacketInfo:
    '''
        Definition of a Packet in the current construct.
        To be constructed from metrics about packet (Ether Info & Packet Meta Info)
    '''
    def __init__(self, timestamp: float,
                 size: int,
                 incoming: bool = False,
                 ip_s: str = None,
                 ip_d: str = None,
                 port_s: int = None,
                 port_d: int = None,
                 proto: str = None,
                 additional: dict = None):

        self.timestamp = timestamp

        self.incoming = incoming

        self.pkt_size = size

        self.flow = {'ip_s': ip_s,
                     'ip_d': ip_d,
                     'port_s': port_s,
                     'port_d': port_d,
                     'proto': proto}

        self.additional_info = additional


class PacketWindow:
    '''
        Definition of window of size 1 Second.
        Used to pass current window Info.
    '''
    def __init__(self, size: float, serial_num: int, label: bool = False):
        self.packets = []
        self.packets_n = 0

        self.window_throughput = 0
        self.window_in_throughput = 0
        self.window_out_throughput = 0

        self.first_timestamp = 0
        self.last_timestamp = 0

        self.size = size
        self.serial_no = serial_num
        self.label = label

        self.additional_info: dict = None

    def append(self, packet: PacketInfo) -> bool:
        '''
            Appends a `PacketInfo` Obj. to the window (self).
            returns True if Append Was Successful, False if packet Beyond Window(in which case, it won't append).
            If recieves None as arg returns false
        '''

        # TODO write PacketWindow.append

class PacketQueue:
    '''
        Queue to define a Generic Packet Window.
        Holds info about N-size window (aggregation) of Packets.
    '''

    def __init__(self, N: int, history: bool = False):
        self.approach = 'history' if history else 'future'

        # packet metrics for given window
        self.total_packets = []
        self.total_packet_num = 0
        self.total_throughput = 0

        # incoming metrics
        self.incoming_packets = []
        self.incoming_packet_num = 0
        self.incoming_throughput = 0

        # outgoing metrics
        self.outgoing_packets = []
        self.outgoing_packet_num = 0
        self.outgoing_throughput = 0

        # window metrics
        self.max_window_size = N
        self.window_at_full_size = False
        self.current_actual_window_size = 0
        self.current_window_fragment = PacketWindow()

        self.first_timestamp = 0
        self.last_full_window_timestamp = 0  # steps of 1(s) from first
        self.current_min_timestamp = 0
        self.current_max_timestamp = 0

    def enqueue(self, packet: PacketWindow):
        # add to total packet queue (append to beginning)

        # add to designated packet queue (in / out)

        # calc new actual window size

        # check if window size bigger then N
        #     yes - deQ last packet and check again

        # calc new total throughput
        # calc new relevant (in / out) throughput

        # update max timestamps (min is updated in `dequeue`)

        # return weather of not a full window has passed
        # TODO write PacketQueue.enqueue

        pass

    def dequeue(self):
        # ...
        # update main timestamps (max is updated in `dequeue`)
        # TODO write PacketQueue.dequeue
        pass

    def get_windows(self, mode: str = 'history'):
        '''
            separates queue into 2 windows; one will be 1 sec long and will be queried upon,
             and the second will be all the rest to be a perspective (future / past)
        '''
        # TODO write PacketQueue.get_windows
        pass