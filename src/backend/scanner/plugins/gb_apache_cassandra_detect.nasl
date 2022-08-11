###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_cassandra_detect.nasl 10878 2018-08-10 08:52:28Z cfischer $
#
# Apache Cassandra Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105065");
  script_version("$Revision: 10878 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 10:52:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-07-18 18:29:45 +0200 (Fri, 18 Jul 2014)");
  script_name("Apache Cassandra Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", # None of the current find_service* is detecting this service so run it early
                      "nessus_detect.nasl"); # See below...
  script_require_ports("Services/unknown", 9160);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("cpe.inc");
include("host_details.inc");

port = get_unknown_port( default:9160 ); # rpc_port can be changed

# nb: Set by nessus_detect.nasl if we have hit a service described in the notes below
# No need to continue here as well...
if( get_kb_item( "generic_echo_test/" + port + "/failed" ) ) exit( 0 );

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test
# multiple times...
if( ! get_kb_item( "generic_echo_test/" + port + "/tested" ) ) {
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  send( socket:soc, data:string( "TestThis\r\n" ) );
  r = recv_line( socket:soc, length:10 );
  close( soc );
  # We don't want to be fooled by echo & the likes
  if( "TestThis" >< r ) {
    set_kb_item( name:"generic_echo_test/" + port + "/failed", value:TRUE );
    exit( 0 );
  }
}

set_kb_item( name:"generic_echo_test/" + port + "/tested", value:TRUE );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

cmd = 'execute_cql3_query';
cmd_len = strlen( cmd ) % 256 ;

sql = 'select release_version from system.local;';
sql_len = strlen( sql ) % 256 ;

req = raw_string( 0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, cmd_len ) +
      cmd +
      raw_string( 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
                  0x00, 0x00, sql_len ) +
      sql +
      raw_string( 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
                  0x03, 0x00, 0x00, 0x00, 0x01, 0x00 );


alen = strlen( req ) % 256;
req = raw_string( 0x00, 0x00, 0x00, alen ) + req;

send( socket:soc, data:req );
recv = recv( socket:soc, length:4096 );
close( soc );
if( ! recv || "execute_cql3_query" >!< recv ) exit( 0 );

# apache casasandra detected
# Note that e.g. Shodan is showing a Version: 19.39.0 but that seems wrong in that case.
vers = "unknown";
install = port + "/tcp";

for( i = 0; i < strlen( recv ); i++ )
{
  if( recv[i] == '\x00' )
    ret += ' ';

  if( isprint( c:recv[i] ) )
    ret += recv[i];
}

version = eregmatch( pattern:"release_version\s*([0-9.]+)", string:ret );
if( ! isnull( version[1] ) ) vers = version[1];

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:apache:cassandra:" );
if( ! cpe )
  cpe = "cpe:/a:apache:cassandra";

set_kb_item( name:"apache/cassandra/detected", value:TRUE );

register_service( port:port, proto:"cassandra" );
register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"Apache Cassandra",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
             port:port,
             expert_info:'Request:\n' + hexdump( ddata:req ) + '\nResponse:\n' + hexdump( ddata:recv )  );

exit( 0 );
