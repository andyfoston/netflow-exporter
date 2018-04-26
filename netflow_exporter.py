#!/usr/bin/env python3

import asyncio
import socket
import struct
from collections import namedtuple
from datetime import datetime, timedelta
from ipaddress import IPv4Address

PROTOCOLS_BY_ID = {getattr(socket, n): n.replace("IPPROTO_", "")
                   for n in dir(socket) if n.startswith("IPPROTO")}

class Flow(namedtuple("Flow", "src_addr dst_addr nexthop src_if dst_if packets octets start end srcport dstport flags protocol tos src_as dst_as src_mask dst_mask")):

    @classmethod
    def parse_v5_v7(cls, data, offset):
        (src_addr, dst_addr, nexthop, src_if, dst_if, packets, octets,
         start, end, srcport, dstport, flags, protocol, tos, src_as,
         dst_as, src_mask, dst_mask) = struct.unpack_from(
             ">IIIHHIIIIHHxBBBHHBB", data, offset=offset
         )
        src_addr = str(IPv4Address(src_addr))
        dst_addr = str(IPv4Address(dst_addr))
        nexthop = str(IPv4Address(nexthop))
        protocol = PROTOCOLS_BY_ID.get(protocol, protocol)

        return cls(src_addr, dst_addr, nexthop, src_if, dst_if, packets, octets,
                   start, end, srcport, dstport, flags, protocol, tos, src_as,
                   dst_as, src_mask, dst_mask)

    def get_flags(self):
        assigned_flags = []
        if self.flags & 32:
            assigned_flags.append("URG")
        if self.flags & 16:
            assigned_flags.append("ACK")
        if self.flags & 8:
            assigned_flags.append("PSH")
        if self.flags & 4:
            assigned_flags.append("RST")
        if self.flags & 2:
            assigned_flags.append("SYN")
        if self.flags & 1:
            assigned_flags.append("FIN")
        return "%s" % ", ".join(assigned_flags)

    def __repr__(self):
        attrs = ["%s=%r" % (n, getattr(self, n)) for n in self._fields]
        attrs.append("flags_desc=%r" % self.get_flags())
        return 'Flow(%s)' % ", ".join(attrs)


class NetflowServerProtocol:
    def connection_made(self, transport):
        pass

    def parse_v5(self, data):
        count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval = struct.unpack_from(">xxHIIIIBBH", data)
        print(count, timedelta(microseconds=int(sys_uptime)),
              datetime.fromtimestamp(float("%d.%d" % (unix_secs, unix_nsecs))),
              flow_sequence, engine_type, engine_id, sampling_interval)
        offset = 24
        for _ in range(count):
            print(Flow.parse_v5_v7(data, offset))
            offset += 48

    def parse_v7(self, data):
        count, sys_uptime, unix_secs, unix_nsecs, flow_sequence = struct.unpack_from(">xxHIIII", data)
        print(count, timedelta(microseconds=int(sys_uptime)),
              datetime.fromtimestamp(float("%d.%d" % (unix_secs, unix_nsecs))),
              flow_sequence)
        offset = 24
        for _ in range(count):
            print(Flow.parse_v5_v7(data, offset))
            offset += 52

    def datagram_received(self, data, addr):
        remote_addr, port = addr
        version, count = struct.unpack_from(">HH", data)
        print("Version: %d. Flow count: %d. Address: %s" % (version, count, remote_addr))
        try:
            getattr(self, "parse_v%d" % version)(data)
        except AttributeError:
            print("Unable to find a parser for version %d traffic" % version)

loop = asyncio.get_event_loop()
print("Starting Netflow server")

listen = loop.create_datagram_endpoint(
    NetflowServerProtocol, local_addr=("0.0.0.0", 2055)
)
transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

transport.close()
loop.close()
