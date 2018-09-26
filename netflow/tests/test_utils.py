#!/usr/bin/env python3

from datetime import datetime, timedelta
from unittest import TestCase, main
from netflow.utils import HeaderTemplateField, TCPFlags, Template, TemplateField

# TODO add tests for setup_logging


class TestTCPFlags(TestCase):
    def test_get_flags(self):
        flags = TCPFlags(63)
        self.assertEqual("URG, ACK, PSH, RST, SYN, FIN", flags.get_flags())

        flags = TCPFlags(24)
        self.assertEqual("ACK, PSH", flags.get_flags())

        flags = TCPFlags(0)
        self.assertEqual("", flags.get_flags())

    def test_int(self):
        flags = TCPFlags(63)
        self.assertEqual(int(flags), 63)

    def test_str(self):
        flags = TCPFlags(63)
        self.assertEqual("63 (URG, ACK, PSH, RST, SYN, FIN)", str(flags))

    def test_repr(self):
        flags = TCPFlags(63)
        self.assertEqual("TCPFlags(63 (URG, ACK, PSH, RST, SYN, FIN))", repr(flags))


class TestTemplateField(TestCase):
    def test_name(self):
        field = TemplateField(field_type_id=8, bytes=4)
        self.assertEqual("ipv4_src_addr", field.name)

        # Invalid field_type_id
        field = TemplateField(field_type_id=-1, bytes=4)
        self.assertEqual("unknown (-1)", field.name)

    def test_struct_format(self):
        field = TemplateField(field_type_id=8, bytes=4)
        self.assertEqual("I", field.struct_format)

    def test_parse_field_tcpflags(self):
        field = TemplateField(
            field_type_id=TemplateField.TYPE_BY_NAME["tcp_flags"], bytes=1
        )
        self.assertIsInstance(field.parse_field(63), TCPFlags)

    def test_parse_field_protocol(self):
        field = TemplateField(
            field_type_id=TemplateField.TYPE_BY_NAME["protocol"], bytes=1
        )
        self.assertEqual(field.parse_field(6), "TCP")

    def test_parse_field_ipv4_address(self):
        field = TemplateField(
            field_type_id=TemplateField.TYPE_BY_NAME["ipv4_src_addr"], bytes=4
        )
        self.assertEqual(field.parse_field(167772161), "10.0.0.1")

    def test_parse_field_ipv6_address(self):
        field = TemplateField(
            field_type_id=TemplateField.TYPE_BY_NAME["ipv6_src_addr"], bytes=16
        )
        self.assertEqual(field.parse_field(
            338288524927261089654018896841347694593
        ), "fe80::1")

    def test_parse_field_source_port(self):
        field = TemplateField(
            field_type_id=TemplateField.TYPE_BY_NAME["src_port"], bytes=2
        )
        self.assertEqual(field.parse_field(80), 80)


class TestHeaderTemplateField(TestCase):
    def test_struct_format(self):
        field = HeaderTemplateField(name="count", bytes=2)
        self.assertEqual(field.struct_format, "H")

    def test_parse_field_uptime(self):
        field = HeaderTemplateField(name="sys_uptime", bytes=4)
        self.assertEqual(field.parse_field(10), timedelta(microseconds=10))

    def test_parse_field_count(self):
        field = HeaderTemplateField(name="count", bytes=2)
        self.assertEqual(field.parse_field(10), 10)


class TestTemplate(TestCase):
    def test_init(self):
        template = Template(fields=[])
        self.assertTrue(template.expiry > datetime.now())

        template = Template(fields=[], expires=False)
        self.assertIsNone(template.expiry)

    def test_struct_format(self):
        template = Template.HEADER_TEMPLATES[5]
        self.assertEqual(template.struct_format, ">xxHIIIIBBH")

    def test_fields_with_data(self):
        template = Template.HEADER_TEMPLATES[5]
        fields = list(template.fields_with_data)
        # Two padding bytes shouldn't exist in this list
        self.assertEqual(len(fields), 8)
        self.assertTrue(all(field.bytes > 0 for field in fields))

    def test_parse_data(self):
        # TODO test this
        pass

    def test_bytes(self):
        template = Template.HEADER_TEMPLATES[5]
        # Padding bytes should be treated as 1 byte
        self.assertEqual(template.bytes, 24)

    def test_create_template(self):
        # TODO test this
        pass


if __name__ == '__main__':
    main()
