###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_maxdb_detect.nasl 8626 2018-02-01 13:23:00Z cfischer $
#
# SAP MaxDB Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100540");
  script_version("$Revision: 8626 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-01 14:23:00 +0100 (Thu, 01 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-03-17 21:52:47 +0100 (Wed, 17 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SAP MaxDB Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 7210);

  script_xref(name:"URL", value:"http://www.sdn.sap.com/irj/sdn/maxdb");

  script_tag(name:"summary", value:"This host is running SAP MaxDB. MaxDB is an ANSI SQL-92 (entry level) compliant
  relational database management system (RDBMS) from SAP AG.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:7210 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x5A,0x00,0x00,0x00,0x03,0x5B,0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
                  0x00,0x00,0x04,0x00,0x5A,0x00,0x00,0x00,0x00,0x02,0x42,0x00,0x04,0x09,0x00,0x00,
                  0x00,0x40,0x00,0x00,0xD0,0x3F,0x00,0x00,0x00,0x40,0x00,0x00,0x70,0x00,0x00,0x00,
                  0x00,0x07,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,
                  0x07,0x49,0x33,0x34,0x33,0x32,0x00,0x04,0x50,0x1C,0x2A,0x03,0x52,0x01,0x03,0x72,
                  0x01,0x09,0x70,0x64,0x62,0x6D,0x73,0x72,0x76,0x00 );

send( socket:soc, data:req );
buf = recv( socket:soc, length:2048 );

if( "pdbmsrv" >!< buf ) {
  close( soc );
  exit( 0 );
}

db_version = raw_string( 0x28,0x00,0x00,0x00,0x03,0x3f,0x00,0x00,0x01,0x00,0x00,0x00,0xc0,0x0b,0x00,0x00,
                         0x00,0x00,0x04,0x00,0x28,0x00,0x00,0x00,0x64,0x62,0x6d,0x5f,0x76,0x65,0x72,0x73,
                         0x69,0x6f,0x6e,0x20,0x20,0x20,0x20,0x20 );

send( socket:soc, data:db_version );
buf = recv( socket:soc, length:2048 );
close( soc );

if( "VERSION" >!< buf ) exit( 0 );

set_kb_item( name:"sap_maxdb/installed", value:TRUE );
register_service( port:port, proto:"sap_maxdb" );

lines = split( buf, sep:'\n', keep:FALSE );

foreach line( lines ) {

  data = eregmatch( pattern:"^([^ =]+) *= *(.*)$", string:line );

  if( ! isnull( data[1] ) && ! isnull( data[2] ) ) {

    if( data[1] == "VERSION" ) {
      version = data[2];
      set_kb_item( name:"sap_maxdb/" + port + "/version", value:version );
    } else if( data[1] == "BUILD" ) {

      build = eregmatch( pattern:"Build ([0-9-]+)", string:data[2] );

      if( ! isnull( build[1] ) ) {
        set_kb_item( name:"sap_maxdb/" + port + "/build", value:build[1] );
      }
    }
    info += data[1] + " : " + data[2] + '\n';
  }
}

if( version ) {
  cpe = "cpe:/a:sap:maxdb:" + version;
} else {
  cpe = "cpe:/a:sap:maxdb";
}

if( info ) {
  info  = '\n\nInformation that was gathered:\n\n' + info;
  extra = info;
}

install = port + "/tcp";

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"SAP MaxDB",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:data[1],
                                          extra:extra ),
                                          port:port );

exit( 0 );
