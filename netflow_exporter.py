#!/usr/bin/env python3

import asyncio
import socket
import struct
from collections import namedtuple, OrderedDict
from datetime import datetime, timedelta
from ipaddress import IPv4Address

PROTOCOLS_BY_ID = {getattr(socket, n): n.replace("IPPROTO_", "")
                   for n in dir(socket) if n.startswith("IPPROTO")}

class TCPFlags:
    def __init__(self, flags):
        self.flags = flags

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
        return ", ".join(assigned_flags)

    def __int__(self):
        return self.flags

    def __str__(self):
        return "%d (%s)" % (self.flags, self.get_flags())

    def __repr__(self):
        return "TCPFlags(%s)" % self

class TemplateField(namedtuple("TemplateField", "field_type_id bytes")):
    FORMAT = {0: "x", # O == unused byte
              1: "B", 2: "H", 4: "I", 8: "Q"}
    TYPES = {1: "in_bytes",
             2: "in_pkts",
             3: "flows",
             4: "protocol",
             5: "src_tos",
             6: "tcp_flags",
             7: "src_port",
             8: "ipv4_src_addr",
             9: "src_mask",
             10: "input_snmp",
             11: "dst_port",
             12: "ipv4_dst_addr",
             13: "dst_mask",
             14: "output_snmp",
             15: "ipv4_next_hop",
             16: "src_as",
             17: "dst_as",
             18: "bgp_ipv4_next_hop",
             19: "multi_dst_pkts",
             20: "multi_dst_bytes",
             21: "last_switched",
             22: "first_switched",
            }

    TYPE_BY_NAME = {v: k for k, v in TYPES.items()}

    @property
    def name(self):
        return self.TYPES.get(self.field_type_id, "")

    @property
    def struct_format(self):
        return self.FORMAT[self.bytes]

    def parse_field(self, data):
        name = self.name
        if name == "tcp_flags":
            return TCPFlags(data)
        elif name == "protocol":
            return PROTOCOLS_BY_ID.get(data, data)
        elif name.startswith("ipv4_"):
           return str(IPv4Address(data))
        else:
            return data

class HeaderTemplateField(namedtuple("HeaderTemplateField", "name bytes")):
    FORMAT = {0: "x", # O == unused byte
              1: "B", 2: "H", 4: "I", 8: "Q"}

    @property
    def struct_format(self):
        return self.FORMAT[self.bytes]

    def parse_field(self, data):
        if self.name == "sys_uptime":
            return timedelta(microseconds=int(data))
        else:
            return data

class Template:
    HEADER_TEMPLATES = {}
    TEMPLATES = {}
    STATIC_TEMPLATES = {}

    def __init__(self, fields):
        self.fields = fields

    def struct_format(self):
        return ">%s" % "".join(f.struct_format for f in self.fields)

    @property
    def fields_with_data(self):
        for field in self.fields:
            if field.bytes > 0:
                yield field

    def parse_data(self, data):
        result = OrderedDict((f.name, f.parse_field(data[i]))
                             for i, f in enumerate(self.fields_with_data)
                            )
        if "unix_secs" in result and "unix_nsecs" in result:
            result["timestamp"] = datetime.fromtimestamp(float("%(unix_secs)d.%(unix_nsecs)d" % result))
            del result["unix_secs"]
            del result["unix_nsecs"]

        return result

    @property
    def bytes(self):
        return sum(max(f.bytes, 1) for f in self.fields)

Template.HEADER_TEMPLATES[5] = Template(fields=[
    HeaderTemplateField(name="", bytes=0), # Padding byte
    HeaderTemplateField(name="", bytes=0), # Padding byte
    HeaderTemplateField(name="count", bytes=2),
    HeaderTemplateField(name="sys_uptime", bytes=4),
    HeaderTemplateField(name="unix_secs", bytes=4),
    HeaderTemplateField(name="unix_nsecs", bytes=4),
    HeaderTemplateField(name="flow_sequence", bytes=4),
    HeaderTemplateField(name="engine_type", bytes=1),
    HeaderTemplateField(name="engine_id", bytes=1),
    HeaderTemplateField(name="sampling_interval", bytes=2),
])

Template.STATIC_TEMPLATES[5] = Template(fields=[
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["ipv4_src_addr"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["ipv4_dst_addr"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["ipv4_next_hop"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["input_snmp"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["output_snmp"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["in_pkts"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["in_bytes"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["first_switched"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["last_switched"], bytes=4),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_port"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["dst_port"], bytes=2),
    TemplateField(field_type_id=-1, bytes=0), # Padding byte
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["tcp_flags"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["protocol"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_tos"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_as"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["dst_as"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_mask"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["dst_mask"], bytes=1),
    TemplateField(field_type_id=-1, bytes=0), # Padding byte
    TemplateField(field_type_id=-1, bytes=0), # Padding byte
])

class NetflowServerProtocol:
    def connection_made(self, _):
        pass

    def parse(self, version, _, data):
        header_template = Template.HEADER_TEMPLATES[version]
        result = struct.unpack_from(header_template.struct_format(), data)
        result = header_template.parse_data(result)
        print(result)
        offset = header_template.bytes

        if version in Template.STATIC_TEMPLATES:
            self.parse_with_static_template(version, result["count"], data, offset)

    def parse_with_static_template(self, version, count, data, offset):
        for _ in range(count):
            template = Template.STATIC_TEMPLATES[version]
            result = struct.unpack_from(template.struct_format(), data, offset=offset)
            print(template.parse_data(result))
            offset += template.bytes

    def datagram_received(self, data, addr):
        remote_addr, _ = addr
        version, = struct.unpack_from(">H", data)
        print("Version: %d. Remote address: %s" % (version, remote_addr))
        try:
            self.parse(version, remote_addr, data)
        except KeyError:
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
