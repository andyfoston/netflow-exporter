#!/usr/bin/env python3

import asyncio
import logging
import os
import socket
import struct
import sys
from collections import namedtuple, OrderedDict
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address

CLEANUP_INTERVAL = 60 * 5
PROTOCOLS_BY_ID = {getattr(socket, n): n.replace("IPPROTO_", "")
                   for n in dir(socket) if n.startswith("IPPROTO")}

def setup_logging():
    def _get_filename():
        # Determine file to log to.
        try:
            main = os.path.abspath(sys.modules["__main__"].__file__)
        except AttributeError:
            main = "interactive"
        return os.path.splitext(os.path.basename(main))[0].replace("%", "%%")

    # "2018-05-17 16:09:59,802: logname[processid]: DEBUG: Done"
    LOG_FORMAT = "%%(asctime)s: %s[%%(process)d]: %%(levelname)s: %%(message)s" % _get_filename()
    logger = logging.getLogger()
    formatter = logging.Formatter(LOG_FORMAT)
    console_handle = sys.stderr
    handler = logging.StreamHandler(console_handle)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    filename = _get_filename() + ".log"
    path = os.path.join("/var/log/", filename)
    handler = logging.FileHandler(path)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    level = logging.INFO
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG)

setup_logging()

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
    FORMAT = {0: "x",  # O == unused byte
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
             23: "out_bytes",
             24: "out_pkts",
             25: "min_pkt_lngth",
             26: "max_pkt_lngth",
             27: "ipv6_src_addr",
             28: "ipv6_dst_addr",
             29: "ipv6_src_mask",
             30: "ipv6_dst_mask",
             31: "ipv6_flow_label",
             32: "icmp_type",
             33: "mul_igmp_type",
             34: "sampling_interval",
             35: "sampling_algorithm",
             36: "flow_active_timeout",
             37: "flow_inactive_timeout",
             38: "engine_type",
             39: "engine_id",
             40: "total_bytes_exp",
             41: "total_pkts_exp",
             42: "total_flow_exp",
             # 43 - Vendor Proprietary
             44: "ipv4_src_prefix",
             45: "ipv4_dst_prefix",
             46: "mpls_top_label_type",
             47: "mpls_top_label_ip_addr",
             48: "flow_sampler_id",
             49: "flow_sampler_mode",
             50: "flow_sampler_random_interval",
             # 51 - Vendor Proprietary
             52: "min_ttl",
             53: "max_ttl",
             54: "ipv4_ident",
             55: "dst_tos",
             56: "in_src_mac",
             57: "out_dst_mac",
             58: "src_vlan",
             59: "dst_vlan",
             60: "ip_protocol_version",
             61: "direction",
             62: "ipv6_next_hop",
             63: "bgp_ipv6_next_hop",
             64: "ipv6_option_headers",
             # 65 - 69 - Vendor Proprietary
             70: "mpls_label_1",
             71: "mpls_label_2",
             72: "mpls_label_3",
             73: "mpls_label_4",
             74: "mpls_label_5",
             75: "mpls_label_6",
             76: "mpls_label_7",
             77: "mpls_label_8",
             78: "mpls_label_9",
             79: "mpls_label_10",
             80: "in_dst_mac",
             81: "out_src_mac",
             82: "if_name",
             83: "if_desc",
             84: "sampler_name",
             85: "in_permanent_bytes",
             86: "in_permanent_pkts",
             # 87 - Vendor Proprietary
            }

    TYPE_BY_NAME = {v: k for k, v in TYPES.items()}

    @property
    def name(self):
        return self.TYPES.get(self.field_type_id, "unknown (%d)" % self.field_type_id)

    @property
    def struct_format(self):
        return self.FORMAT[self.bytes]

    def parse_field(self, data):
        name = self.name
        if name == "tcp_flags":
            return TCPFlags(data)
        elif name == "protocol":
            return PROTOCOLS_BY_ID.get(data, data)
        elif name in ("ipv4_src_addr", "ipv4_dst_addr", "ipv4_next_hop", "bgp_ipv4_next_hop"):
            return str(IPv4Address(data))
        elif name in ("ipv6_src_addr", "ipv6_dst_addr", "ipv6_next_hop", "bgp_ipv6_next_hop"):
            return str(IPv6Address(data))
        return data


class HeaderTemplateField(namedtuple("HeaderTemplateField", "name bytes")):
    FORMAT = {0: "x",  # O == unused byte
              1: "B", 2: "H", 4: "I", 8: "Q"}

    @property
    def struct_format(self):
        return self.FORMAT[self.bytes]

    def parse_field(self, data):
        if self.name == "sys_uptime":
            return timedelta(microseconds=int(data))
        return data


class Template:
    HEADER_TEMPLATES = {}
    TEMPLATES = {}
    STATIC_TEMPLATES = {}

    def __init__(self, fields, expires=True):
        self.fields = fields
        if expires:
            self.expiry = datetime.now() + timedelta(hours=1)
        else:
            self.expiry = None

    @property
    def struct_format(self):
        return ">%s" % "".join(f.struct_format for f in self.fields)

    @property
    def fields_with_data(self):
        for field in self.fields:
            if field.bytes > 0:
                yield field

    def parse_data(self, data, offset=0):
        data = struct.unpack_from(self.struct_format, data, offset=offset)
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

    @classmethod
    def create_template(cls, remote_addr, data, offset):
        template_id, count = struct.unpack_from(">HH", data, offset=offset)
        template = cls(fields=[
            TemplateField(*struct.unpack_from(">HH", data, offset=offset + (i * 4)))
            for i in range(1, count + 1)]
        )
        cls.TEMPLATES[(remote_addr, template_id)] = template
        return template, count * 4


Template.HEADER_TEMPLATES[5] = Template(expires=False, fields=[
    HeaderTemplateField(name="", bytes=0),  # Padding byte
    HeaderTemplateField(name="", bytes=0),  # Padding byte
    HeaderTemplateField(name="count", bytes=2),
    HeaderTemplateField(name="sys_uptime", bytes=4),
    HeaderTemplateField(name="unix_secs", bytes=4),
    HeaderTemplateField(name="unix_nsecs", bytes=4),
    HeaderTemplateField(name="flow_sequence", bytes=4),
    HeaderTemplateField(name="engine_type", bytes=1),
    HeaderTemplateField(name="engine_id", bytes=1),
    HeaderTemplateField(name="sampling_interval", bytes=2),
])
Template.HEADER_TEMPLATES[9] = Template(expires=False, fields=[
    HeaderTemplateField(name="", bytes=0),  # Padding byte
    HeaderTemplateField(name="", bytes=0),  # Padding byte
    HeaderTemplateField(name="count", bytes=2),
    HeaderTemplateField(name="sys_uptime", bytes=4),
    HeaderTemplateField(name="unix_secs", bytes=4),
    HeaderTemplateField(name="package_sequence", bytes=4),
    HeaderTemplateField(name="source_id", bytes=4),
])

Template.STATIC_TEMPLATES[5] = Template(expires=False, fields=[
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
    TemplateField(field_type_id=-1, bytes=0),  # Padding byte
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["tcp_flags"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["protocol"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_tos"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_as"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["dst_as"], bytes=2),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["src_mask"], bytes=1),
    TemplateField(field_type_id=TemplateField.TYPE_BY_NAME["dst_mask"], bytes=1),
    TemplateField(field_type_id=-1, bytes=0),  # Padding byte
    TemplateField(field_type_id=-1, bytes=0),  # Padding byte
])


class NetflowServerProtocol:
    def connection_made(self, _):
        pass

    def parse_with_static_template(self, version, count, data, offset):
        for _ in range(count):
            template = Template.STATIC_TEMPLATES[version]
            logging.info("Flow: %s", template.parse_data(data, offset=offset))
            offset += template.bytes

    def datagram_received(self, data, addr):
        remote_addr, _ = addr
        version, = struct.unpack_from(">H", data)
        logging.info("Version: %d. Remote address: %s", version, remote_addr)
        try:
            header_template = Template.HEADER_TEMPLATES[version]
        except KeyError:
            logging.error("Unable to find a parser for version %d traffic", version)
            return
        result = header_template.parse_data(data)
        logging.info("Header: %s", result)
        offset = header_template.bytes

        if version in Template.STATIC_TEMPLATES:
            self.parse_with_static_template(version, result["count"], data, offset)
        else:
            count = result["count"]
            processed = 0
            while processed < count:
                flowset_id, flowset_length = struct.unpack_from(">HH", data, offset=offset)
                position = 0
                while position < flowset_length:
                    if flowset_id == 0:
                        template, template_length = Template.create_template(remote_addr, data, offset=offset + 4)
                        offset += template_length
                        position += template_length
                    elif flowset_id == 1:
                        logging.debug("Options Template %d found. Skipping", flowset_id)
                        # The length of this flow isn't known, so skip the
                        # remainder of this packet. TODO work out the length
                        # of this packet.
                        return
                    elif flowset_id > 255:
                        try:
                            template = Template.TEMPLATES[(remote_addr, flowset_id)]
                        except KeyError:
                            logging.error("Template %d not found", flowset_id)
                            # The length of this flow isn't known, so skip the
                            # remainder of this packet. TODO work out the length
                            # of this packet.
                            return
                        else:
                            result = template.parse_data(data, offset=offset + 4)
                            print(result)
                            offset += template.bytes
                            position += template.bytes + 1
                    else:
                        logging.debug("Options record %d found. Skipping", flowset_id)
                        # The length of this flow isn't known, so skip the
                        # remainder of this packet. TODO process this.
                        return
                    processed += 1

@asyncio.coroutine
def cleanup_old_templates():
    while True:
        yield from asyncio.sleep(CLEANUP_INTERVAL)
        logging.info("Cleaning up old templates")
        keys_to_remove = []
        for key, template in Template.TEMPLATES.items():
            if template.expiry and template.expiry <= datetime.now():
                keys_to_remove.append(key)

        for key in keys_to_remove:
            logging.debug("Deleting template: %s", key)
            del Template.TEMPLATES[key]

cleanup_task = asyncio.Task(cleanup_old_templates())

loop = asyncio.get_event_loop()
logging.info("Starting Netflow server")

listen = loop.create_datagram_endpoint(
    NetflowServerProtocol, local_addr=("0.0.0.0", 2055)
)
transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_until_complete(cleanup_task)
    loop.run_forever()
except KeyboardInterrupt:
    # Hack to stop an error being displayed and an exit code of 1 being returned
    # because the cleanup task hasn't completed
    cleanup_task.set_result(None)
except Exception as ex:
    logging.error("Unexpected error raised")
    logging.exception(ex)
    raise
finally:
    logging.info("Stopping Netflow server")
    transport.close()
    loop.close()
