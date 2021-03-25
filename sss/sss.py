#!/usr/bin/python3

# 2021 Collegiate eCTF
# SCEWL Security Server
# Ben Janis
#
# (c) 2021 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2021 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2021 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

import socket
import select
import struct
import argparse
import logging
import os
import secrets
from typing import NamedTuple


SSS_IP = 'localhost'
SSS_ID = 1

# mirroring scewl enum at scewl.c:4
ALREADY, REG, DEREG = -1, 0, 1

logging.basicConfig(level=logging.INFO)

Device = NamedTuple('Device', [('id', int), ('status', int), ('csock', socket.socket)])


class SSS:
    def __init__(self, sockf):
        # Make sure the socket does not already exist
        try:
            os.unlink(sockf)
        except OSError:
            if os.path.exists(sockf):
                raise

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(sockf)
        self.sock.listen(10)
        self.devs = {}
    
    @staticmethod
    def sock_ready(sock, op='r'):
        rready, wready, _ = select.select([sock], [sock], [], 0)
        return rready if op == 'r' else wready

    def handle_transaction(self, csock: socket.SocketType):
        logging.debug('handling transaction')
        data = b''
        while len(data) < 12:
            recvd = csock.recv(12 - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')
        _, _, _, _, dev_id, op, scewl_secret = struct.unpack('<HHHHHH64s', data)

        # read in corresponding scewl secret
        
        scewl_secret = dev_id + "_secret"
        if os.path.exists(scewl_secret):
            with open(scewl_secret, "rb") as f:
                checked_secret = f.read(64)
                # check scewl_secret mismatch
                if checked_secret != scewl_secret:
                    resp_op = ALREADY
                    logging.info(f'{dev_id}:key mismatch')
                    body = struct.pack('<Hh', dev_id, resp_op)
                # requesting repeat transaction
                elif dev_id in self.devs and self.devs[dev_id].status == op:
                    resp_op = ALREADY
                    logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
                    body = struct.pack('<Hh', dev_id, resp_op)
                # record registration transaction and read in keys
                # aes key is 16 bytes, hmac 64, seed 32
                elif(op == REG):
                    self.devs[dev_id] = Device(dev_id, REG, csock)
                    resp_op = REG
                    with open("aes_key", "rb") as f:
                        aes_key = f.read(16)
                    with open("hmac_key", "rb") as f:
                        hmac_key = f.read(64)
                    logging.info(f'{dev_id}:Registered')
                    seed = secrets.token_bytes(32)
                    body = struct.pack('<Hh16s32s64s', dev_id, resp_op, aes_key, seed, hmac_key)
                # record deregistration
                else:
                    self.devs[dev_id] = Device(dev_id, DEREG, csock)
                    resp_op = DEREG
                    logging.info(f'{dev_id}:Deregistered')
                    body = struct.pack('<Hh', dev_id, resp_op)
        else:
            resp_op = ALREADY
            logging.info(f'{dev_id}:bad ID')
            body = struct.pack('<Hh', dev_id, resp_op)

        # send response
        resp = struct.pack('<2sHHH', b'SC', dev_id, SSS_ID, len(body)) + body
        logging.debug(f'Sending response {repr(data)}')
        csock.send(resp)

    def start(self):
        unattributed_socks = set()

        # serve forever
        while True:
            # check for new client
            if self.sock_ready(self.sock):
                csock, _ = self.sock.accept()
                logging.info(f':New connection')
                unattributed_socks.add(csock)
                continue

            # check pool of unattributed sockets first
            for csock in unattributed_socks:
                try:
                    if self.sock_ready(csock):
                        self.handle_transaction(csock)
                        unattributed_socks.remove(csock)
                        break
                except (ConnectionResetError, BrokenPipeError):
                    logging.info(':Connection closed')
                    unattributed_socks.remove(csock)
                    csock.close()
                    break
            
            # check pool of attributed sockets first
            old_ids = []
            for dev in self.devs.values():
                if dev.csock and self.sock_ready(dev.csock):
                    try:
                        self.handle_transaction(dev.csock)
                    except (ConnectionResetError, BrokenPipeError):
                        logging.info(f'{dev.id}:Connection closed')
                        dev.csock.close()
                        old_ids.append(dev.id)
            
            for dev_id in old_ids:
                del self.devs[dev_id]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('sockf', help='Path to socket to bind the SSS to')
    return parser.parse_args()


def main():
    args = parse_args()
    # map of SCEWL IDs to statuses
    sss = SSS(args.sockf)
    sss.start()


if __name__ == '__main__':
    main()
