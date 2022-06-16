/* -*- P4_16 -*- */

/*
 * P4 Calculator
 *
 * This program implements a simple protocol. It can be carried over Ethernet
 * (Ethertype 0x1234).
 *
 * The Protocol header looks like this:
 *
 *        0                1                  2              3
 * +----------------+----------------+----------------+---------------+
 * |      P         |       4        |     Version    |     Op        |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand A                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Operand B                           |
 * +----------------+----------------+----------------+---------------+
 * |                              Result                              |
 * +----------------+----------------+----------------+---------------+
 *
 * P is an ASCII Letter 'P' (0x50)
 * 4 is an ASCII Letter '4' (0x34)
 * Version is currently 0.1 (0x01)
 * Op is an operation to Perform:
 *   'a' (0x61) 
 *   'b' (0x62) 
 *   'c' (0x63) 
 *   '1' (0x31) 
 *   '2' (0x32) 
 *   '3' (0x33) 
 *
 * The device receives a packet, performs the requested operation, fills in the
 * result and sends the packet back out of the same port it came in on, while
 * swapping the source and destination addresses.
 *
 * If an unknown operation is specified or the header is not valid, the packet
 * is dropped
 */

#include <core.p4>
#include <v1model.p4>

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
 * This is a custom protocol header for the calculator. We'll use
 * ethertype 0x1234 for is (see parser)
 */
const bit<16> TICTAC_ETYPE = 0x1234;
const bit<8>  TICTAC_P     = 0x50;   // 'P'
const bit<8>  TICTAC_4     = 0x34;   // '4'
const bit<8>  TICTAC_VER   = 0x01;   // v0.1
const bit<8>  TICTAC_PLUS  = 0x2b;   // '+'
const bit<8>  TICTAC_MINUS = 0x2d;   // '-'
const bit<8>  TICTAC_AND   = 0x26;   // '&'
const bit<8>  TICTAC_OR    = 0x7c;   // '|'
const bit<8>  TICTAC_CARET = 0x5e;   // '^'

header tictac_t {
    bit<8>  p;
    bit<8>  four;
    bit<8>  ver;
    bit<8>  op;
    bit<32> coord1;
    bit<32> coord2;
    bit<32> res;
}

/*
 * All headers, used in the program needs to be assembed into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    tictac_t     tictac;
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
            TICTAC_ETYPE : check_tictac;
            default      : accept;
        }
    }

    state check_tictac {
        transition select(packet.lookahead<tictac_t>().p,
        packet.lookahead<tictac_t>().four,
        packet.lookahead<tictac_t>().ver) {
            (TICTAC_P, TICTAC_4, TICTAC_VER) : parse_tictac;
            default                          : accept;
        }
    }

    state parse_tictac {
        packet.extract(hdr.tictac);
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

    action send_back(bit<32> result) {
        bit<48> tmp;

        /* Put the result back in */
        hdr.tictac.res = result;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action operation_add() {
        send_back(hdr.tictac.coord1 + hdr.tictac.coord2);
    }

    action operation_sub() {
        send_back(hdr.tictac.coord1 - hdr.tictac.coord2);
    }

    action operation_and() {
        send_back(hdr.tictac.coord1 & hdr.tictac.coord2);
    }

    action operation_or() {
        send_back(hdr.tictac.coord1 | hdr.tictac.coord2);
    }

    action operation_xor() {
        send_back(hdr.tictac.coord1 ^ hdr.tictac.coord2);
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    table calculate {
        key = {
            hdr.tictac.op        : exact;
        }
        actions = {
            operation_add;
            operation_sub;
            operation_and;
            operation_or;
            operation_xor;
            operation_drop;
        }
        const default_action = operation_drop();
        const entries = {
            TICTAC_PLUS : operation_add();
            TICTAC_MINUS: operation_sub();
            TICTAC_AND  : operation_and();
            TICTAC_OR   : operation_or();
            TICTAC_CARET: operation_xor();
        }
    }


    apply {
        if (hdr.tictac.isValid()) {
            calculate.apply();
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
        packet.emit(hdr.tictac);
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
