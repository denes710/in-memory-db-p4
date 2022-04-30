/* -*- P4_16 -*- */

/*
 * P4 In-network memory
 *
 * This program implements a simple protocol. It can be carried over Ethernet
 * (Ethertype 0x1234).
 *
 * Hosts can read and write memory in the switch. The in-network memory can be
 * shared with different servers. A simple locking mechanims is implemented to
 * ensuer consistency.
 *
 * The Protocol main header looks like this:
 *
 *         0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |   Op  |  Res  |
 * +----------------+----------------+----------------+---------------+
 * |                                Key                               |
 * +----------------+----------------+----------------+---------------+
 *
 * P is an ASCII Letter 'P' (0x50)
 * 4 is an ASCII Letter '4' (0x34)
 * Version is currently 0.1 (0x01)
 * Op is an operation to perform:
 *   0x01 Reading
 *   0x02 Writing
 *   0x03 Locking
 *   0x04 Unlocking
 *   0x05 Reading then locking
 *   0x06 Writing then unlocking
 * Res is the result of the requested operation:
 *   0x00 None (input packet)
 *   0x01 Successful
 *   0x02 Failed
 *   0x03 Operation is failed, beacuse locking problem
 *
 * Different operations have different input headers to avoid unnecessary byte
 * usage, but all of them include the main header. A Writing and Writing then
 * unlocking operations include an extra value field.
 * An input header can be two types:
 *
 * - Reading / Locking / Unlocking / Reading then locking:
 *
 *         0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |   Op  |  Res  |
 * +----------------+----------------+----------------+---------------+
 * |                                Key                               |
 * +----------------+----------------+----------------+---------------+
 *
 * - Writing / Writing then unlocking:
 *
 *         0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |   Op  |  Res  |
 * +----------------+----------------+----------------+---------------+
 * |                                Key                               |
 * +----------------+----------------+----------------+---------------+
 * |                               Value                              |
 * +----------------+----------------+----------------+---------------+
 *
 * A response header can be two types:
 *
 * - Reading / Reading then locking / Writing / Writing then unlocking:
 *
 *         0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |   Op  |  Res  |
 * +----------------+----------------+----------------+---------------+
 * |                                Key                               |
 * +----------------+----------------+----------------+---------------+
 * |                               Value                              |
 * +----------------+----------------+----------------+---------------+
 *
 * - Locking / Unlocking:
 *
 *         0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |   Op  |  Res  |
 * +----------------+----------------+----------------+---------------+
 * |                                Key                               |
 * +----------------+----------------+----------------+---------------+
 *
 * The device receives a packet, performs the requested operation if the
 * consistency is not demaged, chooses the corresponding header for
 * the response and sends the packet back out of the same port it came in on,
 * while swapping the source and destination addresses.
 *
 * The device keeps track of the corresponding IP addresses to the locks.
 * Thus, only that who did the locking can unlock and write the given record
 * if the given key is locked from that IP.
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped.
 */

#include <core.p4>
#include <v1model.p4>

/*
 * Define the constants the program will recognize
 */

#define MAX_SIZE 0x10000

const bit<16> P4INM_ETYPE = 0x1234;
const bit<8>  P4INM_P     = 0x50;   // 'P'
const bit<8>  P4INM_4     = 0x34;   // '4'
const bit<8>  P4INM_VER   = 0x01;   // v0.1

// operations
const bit<4>  P4INM_READING         = 0x01;      // Reading
const bit<4>  P4INM_WRITING         = 0x02;      // Writing
const bit<4>  P4INM_LOCKING         = 0x03;      // Locking
const bit<4>  P4INM_UNLOCKING       = 0x04;      // Unlocking
const bit<4>  P4INM_READINGLOCK     = 0x05;      // Reading then locking
const bit<4>  P4INM_WRITINGUNLOCK   = 0x06;      // Wrigin then unlocking

// result types
const bit<4>  P4INM_NONE        = 0x00;   // None (input packet)
const bit<4>  P4INM_SUCCESSFUL  = 0x01;   // Succesful
const bit<4>  P4INM_FAILED      = 0x02;   // Failed
const bit<4>  P4INM_LOCKERROR   = 0x03;   // Operation failed, because lock

/*
 * Define the headers the program will recognize
 */

/*
 * Standard ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * In-memory data management header.
 */
header p4in_memory_main_t {
    bit<8>  p;
    bit<8>  four;
    bit<8>  ver;
    bit<4>  op;
    bit<4>  res;
    bit<32> key;
}

/*
 * Optional in-memory data header.
 */
header p4in_memory_value_t {
    bit<32>  value;
}

/*
 * All headers, used in the program needs to be assembed into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t          ethernet;
    p4in_memory_main_t  p4in_memory_main;
    p4in_memory_value_t p4in_memory_value;
}

/*
 * All metadata, globally used in the program, also  needs to be assembed
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4INM_ETYPE : check_p4inm;
            default     : accept;
        }
    }

    state check_p4inm {
        transition select(packet.lookahead<p4in_memory_main_t>().p,
        packet.lookahead<p4in_memory_main_t>().four,
        packet.lookahead<p4in_memory_main_t>().ver) {
            (P4INM_P, P4INM_4, P4INM_VER) : parse_p4main;
            default                       : accept;
        }
    }

    state parse_p4main {
        packet.extract(hdr.p4in_memory_main);
        transition select(hdr.p4in_memory_main.op) {
            P4INM_WRITING       : parse_p4value;
            P4INM_WRITINGUNLOCK : parse_p4value;
            default     : accept;
        }
    }

    state parse_p4value {
        packet.extract(hdr.p4in_memory_value);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_SIZE) values;
    register<bit<48>>(MAX_SIZE) lockers;
    register<bit>(MAX_SIZE) is_lockeds;

    bit<32> value;
    bit<48> locker;
    bit     is_locked;

    action send_back(bit<4> result) {
        bit<48> tmp;

        /* Put the result back in */
        hdr.p4in_memory_main.res = result;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action reading() {
        values.read(value, hdr.p4in_memory_main.key);
        hdr.p4in_memory_value.setValid();
        hdr.p4in_memory_value.value = value;
    }

    action writing() {
        values.write(hdr.p4in_memory_main.key, hdr.p4in_memory_value.value);
    }

    action locking() {
        lockers.write(hdr.p4in_memory_main.key, hdr.ethernet.srcAddr);
        is_lockeds.write(hdr.p4in_memory_main.key, 1);
    }

    action unlocking() {
        is_lockeds.write(hdr.p4in_memory_main.key, 0);
    }

    action operation_reading() {
        reading();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_writing() {
        writing();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_locking() {
        locking();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_unlocking() {
        unlocking();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_reading_lock() {
        reading();
        locking();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_writing_unlock() {
        writing();
        unlocking();
        send_back(P4INM_SUCCESSFUL);
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    table processing {
        key = {
            hdr.p4in_memory_main.op     : exact;
        }
        actions = {
            operation_reading;
            operation_writing;
            operation_locking;
            operation_unlocking;
            operation_reading_lock;
            operation_writing_unlock;
            operation_drop;
        }
        const default_action = operation_drop();
        const entries = {
            P4INM_READING       : operation_reading();
            P4INM_WRITING       : operation_writing();
            P4INM_LOCKING       : operation_locking();
            P4INM_UNLOCKING     : operation_unlocking();
            P4INM_READINGLOCK   : operation_reading_lock();
            P4INM_WRITINGUNLOCK : operation_writing_unlock();
        }
    }

    apply {
        if (hdr.p4in_memory_main.isValid()) {
            is_lockeds.read(is_locked, hdr.p4in_memory_main.key);
            lockers.read(locker, hdr.p4in_memory_main.key);

            if (is_locked == 1 && locker != hdr.ethernet.srcAddr &&
                hdr.p4in_memory_main.op != P4INM_READING) {
                send_back(P4INM_LOCKERROR);
            } else {
                if ((hdr.p4in_memory_main.op == P4INM_WRITING ||
                    hdr.p4in_memory_main.op == P4INM_WRITINGUNLOCK) &&
                    !hdr.p4in_memory_value.isValid()) {
                    send_back(P4INM_FAILED);
                } else {
                    processing.apply();
                }
            }
        } else {
            operation_drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4in_memory_main);
        packet.emit(hdr.p4in_memory_value);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
