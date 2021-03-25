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
#
# This is the Secure SCEWL Server that handles SED registration and key distribution for any given
# deployment. Minimal changes have been made to the provided source files to allow for a these
# features. It should be noted that any key generation is done within respective dockerfiles and
# this script primarily focuses on verifying an SED as valid and distributing deployment wide keys.
#
# Registration:
# 1) Given any SED with valid dev_id, establish path to SSS registration secret and scewl_secret
# 2) Validate the scewl_secret that resides on the registering SED by comparing to the SSS's
#    registration secret
# 3) Distribute AES key (16B), HMAC key (64B) and Random seed (32B), given a match
# 4) Send some error given a discrepancy
#
# Succesful execution of this procedure means a given SED is valid and may communicate with other
# deployed SEDs while through use of the aformentioned keys. If an SED doesn't receive these keys
# its messages will be thrown out by any receiving SED which is part of the deployment.
#
# Deregistration is handled by sending deregistration message and removing registration secret from
# the SED (see dockerfiles/3_remove_sed.Dockerfile)


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
        while len(data) < 76:
            recvd = csock.recv(76 - len(data))
            data += recvd

            # check for closed connection
            if not recvd:
                raise ConnectionResetError
        logging.debug(f'Received buffer: {repr(data)}')

        # Unpack message received from a given SED
        _, _, _, _, dev_id, op, scewl_secret = struct.unpack('<HHHHHH64s', data)

        '''Message responses are constructed below'''
        
        # Read in corresponding scewl secret
        secret_path = f'/secrets/{dev_id}_secret'
        if os.path.exists(secret_path):
            with open(secret_path, "rb") as secret_file:
                # Read in the registration secret for verification
                checked_secret = secret_file.read(64)

                # Scewl_secret mismatch, registration key provided by SED is invalid. Log this event
                # and back ALREADY resp_op into the response. Without deployment keys, this SED is
                # considered invalid for registration.
                if checked_secret != scewl_secret:
                    logging.info(f'{dev_id}:expected: {checked_secret}, found: {scewl_secret}')
                    resp_op = ALREADY
                    logging.info(f'{dev_id}:key mismatch')
                    body = struct.pack('<Hh', dev_id, resp_op)

                # Requesting repeat transaction in the case that an SED state already reflects the
                # received op. Log this event.
                elif dev_id in self.devs and self.devs[dev_id].status == op:
                    resp_op = ALREADY
                    logging.info(f'{dev_id}:already {"Registered" if op == REG else "Deregistered"}')
                    body = struct.pack('<Hh', dev_id, resp_op)

                # Record registration transaction and read in keys, then pack into response. This is
                # a valid SED which can communicate in the deployment.
                # AES key: 16 bytes
                # HMAC key: 64 bytes
                # Random seed: 32bytes
                elif op == REG:
                    self.devs[dev_id] = Device(dev_id, REG, csock)
                    resp_op = REG
                    with open("/secrets/aes_key", "rb") as aes_file:
                        aes_key = aes_file.read(16)
                    with open("/secrets/hmac_key", "rb") as hmac_file:
                        hmac_key = hmac_file.read(64)
                    logging.info(f'{dev_id}:Registered')
                    seed = secrets.token_bytes(32)
                    body = struct.pack('<Hh16s32s64s', dev_id, resp_op, aes_key, seed, hmac_key)

                # Record deregistration for an SED which was verified previously to register and
                # hasn't already been deregistered.
                else:
                    self.devs[dev_id] = Device(dev_id, DEREG, csock)
                    resp_op = DEREG
                    logging.info(f'{dev_id}:Deregistered')
                    body = struct.pack('<Hh', dev_id, resp_op)
        # Record some error from reading in the SEDs {dev_id}_secrets folder. This may happen if
        # an SED is attempted to register, which should not be included on the deployment as specified
        # by the {dev_id}_secrets folders generated in dockerfiles/2b_create_sed_secrets.Dockerfile
        else:
            resp_op = ALREADY
            logging.info(f'{dev_id}:bad ID')
            body = struct.pack('<Hh', dev_id, resp_op)

        # Send response to SED constructed in the previous section
        resp = struct.pack('<2sHHH', b'SC', dev_id, SSS_ID, len(body)) + body
        logging.debug(f'Sending response {repr(data)}')
        csock.send(resp)

    # The following methods reflect the provided insecure implementation and keep the SSS active
    # to received registration and deregistration messages before responding
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
