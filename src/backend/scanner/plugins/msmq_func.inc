# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# General info:
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/99ddfc1e-8880-4f76-a02a-1f9fd23af98c (2.2 Message Syntax)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/95a3eb21-8534-483c-8969-7dde9a6ae69e (2.2.1 InternalHeader)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/902e3f42-fecb-4fef-acd4-1847ca5dfd7b (2.2.3 EstablishConnection Packet)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/578e8d6d-0ee0-4e1f-ad4d-1e9a3626d034 (2.2.3.1 EstablishConnectionHeader)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/058cdeb4-7a3c-405b-989c-d32b9d6bddae (2.2.19.1 BaseHeader)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/f9bbe350-d70b-4e90-b9c7-d39328653166 (4.1.3 FRAME 3: Establish Connection Request)
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/50da7ea1-eed7-41f9-ba6a-2aa37f5f1e92 (4.1.4 FRAME 4: Establish Connection Response)
# - The Message Queuing (MSMQ): Message Queuing Binary Protocol uses little-endian byte order.

# nb:
# - BYTE_ORDER_LITTLE_ENDIAN
# - Usually defined in byte_func.inc but we can't use the constant from there because
#   openvas-nasl-lint would report this as not declared
set_byte_order( 1 );

# nb: GUID for this protocol / communication seems to be "fixed".
global_var CLIENT_GUID, CLIENT_GUID_FOR_PKT, SERVER_GUID, SERVER_GUID_FOR_PKT;
CLIENT_GUID = "C626EA11-E6B6-9749-9595-9150557358D1";
SERVER_GUID = "FCA09E90-7890-4544-8F11-394C43CD8907";
# nb: Just taken from the examples above to avoid that we need special handling to convert these...
CLIENT_GUID_FOR_PKT = raw_string( 0xD1, 0x58, 0x73, 0x55, 0x50, 0x91, 0x95, 0x95, 0x49, 0x97, 0xB6, 0xE6, 0x11, 0xEA, 0x26, 0xC6 );
SERVER_GUID_FOR_PKT = raw_string( 0x07, 0x89, 0xCD, 0x43, 0x4C, 0x39, 0x11, 0x8F, 0x44, 0x45, 0x90, 0x78, 0x90, 0x9E, 0xA0, 0xFC );

MSMQ_VERSION = raw_string( 0x10 ); # (16)

# @brief Creates a Microsoft Message Queuing (MSMQ) "EstablishConnection" packet
#
# @param debug If set to TRUE a hexdump of the created packet is displayed
#
# @return A raw MSMQ "EstablishConnection" packet
#
function msmq_create_establishconnection_pkt( debug ) {

  local_var debug;
  local_var conn_hdr, int_hdr, pkt_size, base_hdr, pkt;

  conn_hdr = CLIENT_GUID_FOR_PKT +                  # ClientGuid (16 bytes)
             SERVER_GUID_FOR_PKT +                  # ServerGuid (16 bytes)
             mkdword( rand() ) +                    # TimeStamp (4 bytes)
             raw_string( 0x10, 0x03 ) +             # Reserved: 784
             raw_string( 0x00 ) +                   # OperatingSystem: 0
             raw_string( 0x00 ) +                   # Reserved: 0
             # Notes from "2.2.3.1 EstablishConnectionHeader": When the EstablishConnectionHeader is
             # part of a response packet from a server, each byte of this array MUST be filled with
             # the value 0x5A. When the EstablishConnectionHeader is not part of a response packet
             # from a server, each byte in this field contains an uninitialized value.
             mkpad( 512 );                          # Padding (512 bytes)

  int_hdr = raw_string( 0x00, 0x00 ) +              # Reserved (2 bytes)
            raw_string( 0x02, 0x00 );               # Flags (2 bytes)

  pkt_size = strlen( conn_hdr + int_hdr ) + 16;     # nb: Base header is 16 bytes long

  base_hdr = MSMQ_VERSION +                         # VersionNumber (1 byte). From "2.2.19.1 BaseHeader": This field MUST be set to the value 0x10.
             raw_string( 0xc0 ) +                   # Reserved (1 byte). From "2.2.19.1 BaseHeader": This field can be set to any arbitrary value
             raw_string( 0x0b, 0x00 ) +             # Flags (2 bytes). Uses the default from "4.1.3 FRAME 3: Establish Connection Request"
             raw_string( 0x4c, 0x49, 0x4f, 0x52 ) + # Signature (4 bytes). From "2.2.19.1 BaseHeader": This field MUST be set to 0x524F494C.
             mkdword( pkt_size ) +                  # PacketSize (4 bytes). nb: should be always the same as the size is fixed / given.
             raw_string( 0xff, 0xff, 0xff, 0xff );  # TimeToReachQueue (4 bytes).  Uses the default from "4.1.3 FRAME 3: Establish Connection Request"

  pkt = base_hdr + int_hdr + conn_hdr;

  if( debug ) display( "---[ Created MSMQ 'EstablishConnection' packet (length: ", pkt_size, " bytes) ]---", "\n", hexdump( ddata:pkt ) );

  return pkt;
}

# @brief Parses and verifies a "EstablishConnection" response packet received from a Microsoft
#        Message Queuing (MSMQ) service
#
# @param data  The data to parse and verify
#
# @param debug If set to TRUE a hexdump of the passed packet is displayed
#
# @return Returns TRUE if the received packet is a "EstablishConnection" packet, FALSE otherwise
#         and NULL if no data was given.
#
function msmq_parse_establishconnection_pkt( data, debug ) {

  local_var data, debug;
  local_var pkt_size, version;

  if( ! data ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#msmq_parse_establishconnection_pkt" );
    return;
  }

  pkt_size = strlen( data );

  if( debug ) display( "---[ Passed packet / data (length: ", pkt_size, " bytes) ]---", "\n", hexdump( ddata:data ) );

  # nb:
  # - Should be already checked / covered by the calling VT but we're checking here in addition
  # - If we're sure that the expected size is 572 we could also check for exactly this size here
  if( pkt_size < 572 ) {
    if( debug ) display( "---[ Passed packet / data size too short (Expected: >= 572, Received: ", pkt_size, " bytes) ]---" );
    return FALSE;
  }

  # nb: There is not much we can test here as the service seems to be "echoing" the complete sent
  # packet back to us. The only difference seen so far was:
  # - the "Reserved" flag in the "BaseHeader" which seems to be "0x5A" on all tested systems vs. our
  #   sent "0xC0". But the specifications currently says the following below so we can't / shouldn't
  #   use that:
  #   > Reserved for future use. This field can be set to any arbitrary value when sent and MUST be
  #   > ignored on receipt.
  # - A different ServerGuid returned
  #
  # For now we're just checking if the received data contains:
  # - VersionNumber in the header is 16 (0x10)
  # - CLIENT_GUID_FOR_PKT
  #
  # nb: We can't check for SERVER_GUID_FOR_PKT as this seems to be different in the response
  #
  # If we see some "misdetection" in the future we could also check for the packet length == 572
  # as described previously.

  version = data[0];
  if( version != MSMQ_VERSION )
    return FALSE;

  if( CLIENT_GUID_FOR_PKT >!< data )
    return FALSE;

  return TRUE;
}
