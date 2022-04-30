#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import readline
import re
import struct

from enum import IntEnum

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether
from scapy.all import StrFixedLenField, XByteField, IntField, XBitField
from scapy.all import ConditionalField
from scapy.all import bind_layers


class Operations(IntEnum):
    READING       = 1
    WRITING       = 2
    LOCKING       = 3
    UNLOCKING     = 4
    READINGLOCK   = 5
    WRITINGUNLOCK = 6

class Results(IntEnum):
    NONE      = 0
    SUCCESFUL = 1
    FAILED    = 2
    LOCKERROR = 3

is_writing = lambda pkt: pkt.op == Operations.WRITING or \
    pkt.op == Operations.WRITINGUNLOCK

is_none = lambda pkt: pkt.res == 0

is_succesful = lambda pkt: pkt.res == 1

not_simple_lock = lambda pkt: not (pkt.op == Operations.LOCKING or \
    pkt.op == Operations.UNLOCKING)

value_condition = lambda pkt: (is_writing(pkt) and is_none(pkt)) or \
    (is_succesful(pkt) and not_simple_lock(pkt))

class P4inm(Packet):
    name = "P4inm"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    XBitField("op", Operations.READING.value, size=4),
                    XBitField("res", Results.NONE.value, size=4),
                    IntField("key", 0),
                    ConditionalField(IntField("value", 0), value_condition)]

bind_layers(Ether, P4inm, type=0x1234)

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

def num_parser(s, i, ts, last = False):
    pattern = "^\s*([0-9]+)\s*"
    match = re.match(pattern, s[i:])
    if match:
        ts.append(match.group(1))
        return i + match.end(), ts
    if last:
        return len(s), ts
    raise NumParseError('Expected number literal.')

def op_parser(s, i, ts):
    pos = s[i:].find(" ")
    if pos != -1:
        try:
            op = Operations[s[i:pos]]
            ts.append(op)
            return pos + 1, ts
        except Exception as e:
            raise OpParseError("Wrong operation tag.")
    raise OpParseError("Too few arguments.")

def make_seq(p1, p2, last_op = False):
    def parse(s, i, ts, last = last_op):
        i, ts2 = p1(s, i, ts)
        return p2(s, i, ts2, last)
    return parse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src_addr", help = "src addr", \
        default = "00:05:00:00:00:00")
    args = parser.parse_args()

    input_parser = make_seq(op_parser, make_seq(num_parser, num_parser), True)
    input_string = ""
    iface = "eth0"

    while True:
        input_string = input('> ')
        if input_string == "quit":
            break
        try:
            _, inputs = input_parser(input_string, 0, [])
            pkt = None
            if inputs[0] == Operations.WRITING.value or \
                inputs[0] == Operations.WRITINGUNLOCK.value:
                if (len(inputs) < 3):
                    raise NumParseError("Too few arguments for writing.")
                pkt = Ether(src = args.src_addr, \
                            dst = "00:04:00:00:00:00", \
                            type=0x1234) / \
                     P4inm(op = inputs[0], \
                           key = int(inputs[1]), \
                           value = int(inputs[2]))
            else:
                pkt = Ether(src = args.src_addr,
                            dst="00:04:00:00:00:00",
                            type=0x1234) / \
                    P4inm(op = inputs[0], key = int(inputs[1]))
            pkt = pkt/' '

            print("Operation: ", Operations(inputs[0].value).name)

            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            if resp:
                p4inm = resp[P4inm]
                if p4inm:
                    print("Response value: ", Results(p4inm.res).name)
                    if p4inm.value != None:
                        print("Data value: ", p4inm.value)
                else:
                    print("Cannot find p4inm header in the packet")
            else:
                print("Did not receive response")
        except Exception as error:
            print(error)


if __name__ == '__main__':
    main()
