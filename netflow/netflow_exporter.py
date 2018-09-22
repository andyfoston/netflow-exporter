#!/usr/bin/env python3
"""
Script to receive Netflow packets over UDP and send push them via HTTP(S) to a
REST API endpoint  (Not implemented yet).
"""

import asyncio
import logging
import struct
from datetime import datetime

from netflow.utils import setup_logging, Template


CLEANUP_INTERVAL = 60 * 5


class NetflowServerProtocol:
    """
    Receives Netflow datagrams from asyncio and processes them.
    """
    def connection_made(self, *_):
        # Unused method which must be implemented for asyncio
        pass

    @staticmethod
    def parse_with_static_template(version, count, data, offset):
        """
        Parses and logs flows from a static template NetFlow version.
        i.e. version 5.
        """
        for _ in range(count):
            template = Template.STATIC_TEMPLATES[version]
            logging.info("Flow: %s", template.parse_data(data, offset=offset))
            offset += template.bytes

    def datagram_received(self, data, addr):
        """
        Processes the received NetFlow packet.
        """
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


async def cleanup_old_templates():
    """
    Cleans up expired templates.

    Templates are frequently refreshed, so templates that haven't been recreated
    for an extended period of time are assumed to be no longer in use and are
    consuming resources unnecessarily.
    """
    try:
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL)
            logging.info("Cleaning up old templates")
            keys_to_remove = []
            for key, template in Template.TEMPLATES.items():
                if template.expiry and template.expiry <= datetime.now():
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                logging.debug("Deleting template: %s", key)
                del Template.TEMPLATES[key]
    except asyncio.CancelledError:
        logging.debug("Cleanup task has been cancelled")


if __name__ == '__main__':
    setup_logging()
    cleanup_task = asyncio.Task(cleanup_old_templates())

    loop = asyncio.get_event_loop()
    logging.info("Starting Netflow collector")

    listen = loop.create_datagram_endpoint(
        NetflowServerProtocol, local_addr=("0.0.0.0", 2055)
    )
    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_until_complete(cleanup_task)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        logging.error("Unexpected error raised")
        logging.exception(ex)
        raise
    finally:
        logging.info("Stopping Netflow collector")
        cleanup_task.cancel()
        loop.run_until_complete(loop.shutdown_asyncgens())
        transport.close()
        loop.stop()
        loop.close()
