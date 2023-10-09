# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103416");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2012-02-14 10:07:41 +0100 (Tue, 14 Feb 2012)");
  script_name("SNMP Information Detection and Reporting");
  script_category(ACT_SETTINGS);
  script_family("SNMP");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"SNMP based detection and reporting of generic information like
  e.g. the System Description/sysDescr (OID: 1.3.6.1.2.1.1.1.0) gathered from the remote device.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("snmp_func.inc");

function parse_result( data ) {

  local_var data;
  local_var v, ok, oid_len, tmp;

  if( ! data || strlen( data ) < 8 )
    return FALSE;

  for( v = 0; v < strlen( data ); v++ ) {
    if( ord( data[v] ) == 43 && ord( data[v-1] ) == 8 ) {
      ok = TRUE;
      break;
    }
    oid_len = ord( data[v] );
  }

  if( ! ok || oid_len < 8 )
    return FALSE;

  tmp = substr( data, ( v + oid_len + 2 ) );

  if( ! isprint( c:tmp[0] ) )
    tmp = substr( tmp, 1, strlen( tmp ) - 1 );

  return tmp;
}

oid = "1.3.6.1.2.1.1.1.0";

port = snmp_get_port( default:161 );

# Scanner needs to be build against libsnmp or have snmpget installed for extended SNMP
# functionality in e.g. snmp_func.inc.
# nb: This functions should be always there since openvas-scanner version 20.08.1 / via:
# https://github.com/greenbone/openvas-scanner/pull/594
if( defined_func( "snmpv3_get" ) ) {

  extra = "";

  if( res = snmp_get( port:port, oid:oid ) ) {
    set_kb_item( name:"SNMP/" + port + "/sysdescr", value:res );
    set_kb_item( name:"SNMP/sysdescr/available", value:TRUE );
    extra += '\n  System Description (OID: ' + oid + ") :            " + res;
  }

  oid = "1.3.6.1.2.1.1.5.0";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  System Name (OID: ' + oid + ") :                   " + res;
    set_kb_item( name:"SNMP/" + port + "/sysname", value:res );
    set_kb_item( name:"SNMP/" + port + "/sysname/oid", value:oid );
    set_kb_item( name:"SNMP/sysname/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.1.2.0";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  System ObjectID (OID: ' + oid + ") :               " + res;
    set_kb_item( name:"SNMP/" + port + "/sysoid", value:res );
    set_kb_item( name:"SNMP/sysoid/available", value:TRUE );
  }

  # Various from the Entity MIB tree:
  # - https://www.rfc-editor.org/rfc/rfc4133
  # - https://oidref.com/1.3.6.1.2.1.47.1.1.1.1
  oid = "1.3.6.1.2.1.47.1.1.1.1.12.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Manufacturer Name (OID: ' + oid + ") :   " + res;
    set_kb_item( name:"SNMP/" + port + "/manufacturer", value:res );
    set_kb_item( name:"SNMP/" + port + "/manufacturer/oid", value:oid );
    set_kb_item( name:"SNMP/manufacturer/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.13.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Model Name (OID: ' + oid + ") :          " + res;
    set_kb_item( name:"SNMP/" + port + "/model_name", value:res );
    set_kb_item( name:"SNMP/" + port + "/model_name/oid", value:oid );
    set_kb_item( name:"SNMP/model_name/available", value:TRUE );
  }

  # e.g.:
  # Juniper router: Juniper MX240 Internet Backbone Router
  # Arista 7050-SX switch: 48 SFP+ + 4 QSFP+ 1RU
  # Cisco ASR: Cisco ASR1002 Chassis
  oid = "1.3.6.1.2.1.47.1.1.1.1.2.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Physical Description (OID: ' + oid + ") : " + res;
    set_kb_item( name:"SNMP/" + port + "/physicaldescription", value:res );
    set_kb_item( name:"SNMP/" + port + "/physicaldescription/oid", value:oid );
    set_kb_item( name:"SNMP/physicaldescription/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.3.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Physical Vendor Type (OID: ' + oid + ") : " + res;
    set_kb_item( name:"SNMP/" + port + "/physicalvendortype", value:res );
    set_kb_item( name:"SNMP/physicalvendortype/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.7.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Physical Name (OID: ' + oid + ") :        " + res;
    set_kb_item( name:"SNMP/" + port + "/physicalname", value:res );
    set_kb_item( name:"SNMP/" + port + "/physicalname/oid", value:oid );
    set_kb_item( name:"SNMP/physicalname/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.8.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Hardware version (OID: ' + oid + ") :     " + res;
    set_kb_item( name:"SNMP/" + port + "/hw_version", value:res );
    set_kb_item( name:"SNMP/" + port + "/hw_version/oid", value:oid );
    set_kb_item( name:"SNMP/hw_version/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.9.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Firmware version (OID: ' + oid + ") :     " + res;
    set_kb_item( name:"SNMP/" + port + "/fw_version", value:res );
    set_kb_item( name:"SNMP/" + port + "/fw_version/oid", value:oid );
    set_kb_item( name:"SNMP/fw_version/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.10.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Software version (OID: ' + oid + ") :    " + res;
    set_kb_item( name:"SNMP/" + port + "/sw_version", value:res );
    set_kb_item( name:"SNMP/" + port + "/sw_version/oid", value:oid );
    set_kb_item( name:"SNMP/sw_version/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.47.1.1.1.1.11.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Serial Number (OID: ' + oid + ") :       " + res;
    set_kb_item( name:"SNMP/" + port + "/serial_number", value:res );
    set_kb_item( name:"SNMP/" + port + "/serial_number/oid", value:oid );
    set_kb_item( name:"SNMP/serial_number/available", value:TRUE );
  }

  oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  if( res = snmp_get( port:port, oid:oid ) ) {
    extra += '\n  Model Description (OID: ' + oid + ") :      " + res;
    set_kb_item( name:"SNMP/" + port + "/model_description", value:res );
    set_kb_item( name:"SNMP/" + port + "/model_description/oid", value:oid );
    set_kb_item( name:"SNMP/model_description/available", value:TRUE );
  }

  if( extra ) {
    set_kb_item( name:"SNMP/generic_info/available", value:TRUE );
    set_kb_item( name:"SNMP/" + port + "/generic_info/available", value:TRUE );

    report = 'The following SNMP information was extracted from the remote device:\n';
    report += extra;
    log_message( port:port, data:report, proto:"udp" );
  }

  exit( 0 );

}

# nb: This is just a fallback to detect the SNMP sysDescr, however none of the SNMP functions from
# snmp_func.inc will work as they rely on snmpv3_get() as well.
else {

  report = "The following SNMP sysDescr (OID: " + oid + ') was extracted from the remote device:\n\n';
  community = snmp_get_community( port:port );
  if( ! community )
    community = "public";

  soc = open_sock_udp( port );
  if( ! soc )
    exit( 0 );

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen( community );

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;

  for( i = 0; i < 3; i++ ) {

    sendata = raw_string( 0x30, 0x82, len_hi, len_lo,
                          0x02, 0x01, i, 0x04, sz );

    sendata += community +
               raw_string( 0xA1, 0x18, 0x02,
                           0x01, 0x01, 0x02, 0x01,
                           0x00, 0x02, 0x01, 0x00,
                           0x30, 0x0D, 0x30, 0x82,
                           0x00, 0x09, 0x06, 0x05,
                           0x2B, 0x06, 0x01, 0x02,
                           0x01, 0x05, 0x00 );

    send( socket:soc, data:sendata );
    result = recv( socket:soc, length:400, timeout:1 );
    if( ! result || ord( result[0] ) != 48 )
      continue;

    if( res = parse_result( data:result ) ) {

      close( soc );

      set_kb_item( name:"SNMP/" + port + "/sysdescr", value:res );
      set_kb_item( name:"SNMP/sysdescr/available", value:TRUE );

      log_message( port:port, data:report + res, proto:"udp" );
      exit( 0 );
    }
  }
  close( soc );
}

exit( 0 );
