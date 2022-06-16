/* -*- P4_16 -*- */

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
const bit<8>  TICTAC_X     = 0x58;   // 'x'
const bit<8>  TICTAC_O     = 0x4F;   // 'O'


header tictac_t {
    int<32>  user_input;
    bit<32>  field0;
    bit<32>  field1;
    bit<32>  field2;
    bit<32>  field3;
    bit<32>  field4;
    bit<32>  field5;
    bit<32>  field6;
    bit<32>  field7;
    bit<32>  field8;
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

register<bit<32>>(9) matrix;

struct metadata {
    bit<32>  field0;
    bit<32>  field1;
    bit<32>  field2;
    bit<32>  field3;
    bit<32>  field4;
    bit<32>  field5;
    bit<32>  field6;
    bit<32>  field7;
    bit<32>  field8;
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
            TICTAC_ETYPE : parse_tictac;
            default      : accept;
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


    if (user_input == 0) {
        matrix.write(0, TICTAC_X);
    } else if (user_input == 1) {
        matrix.write(1, TICTAC_X);
    } else if (user_input == 2) {
        matrix.write(2, TICTAC_X);
    } else if (user_input == 3) {
        matrix.write(3, TICTAC_X);
    } else if (user_input == 4) {
        matrix.write(4, TICTAC_X);
    } else if (user_input == 5) {
        matrix.write(5, TICTAC_X);
    } else if (user_input == 6) {
        matrix.write(6, TICTAC_X);
    } else if (user_input == 7) {
        matrix.write(7, TICTAC_X);
    } else if (user_input == 8) {
        matrix.write(8, TICTAC_X);
    }

    matrix.read(meta.field0, 0);
    matrix.read(meta.field1, 1);
    matrix.read(meta.field2, 2);
    matrix.read(meta.field3, 3);
    matrix.read(meta.field4, 4);
    matrix.read(meta.field5, 5);
    matrix.read(meta.field6, 6);
    matrix.read(meta.field7, 7);
    matrix.read(meta.field8, 8);

    /* Put the result back in */
    hdr.tictac.field0 = meta.field0;
    hdr.tictac.field1 = meta.field1;
    hdr.tictac.field2 = meta.field2;
    hdr.tictac.field3 = meta.field3;
    hdr.tictac.field4 = meta.field4;
    hdr.tictac.field5 = meta.field5;
    hdr.tictac.field6 = meta.field6;
    hdr.tictac.field7 = meta.field7;
    hdr.tictac.field8 = meta.field8;

    bit<48> tmp;

    /* Swap the MAC addresses */
    tmp = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = tmp;

    /* Send the packet back to the port it came from */
    standard_metadata.egress_spec = standard_metadata.ingress_port;

    
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
