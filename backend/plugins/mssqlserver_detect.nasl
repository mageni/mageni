###############################################################################
# OpenVAS Vulnerability Test
# $Id: mssqlserver_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Microsoft SQL TCP/IP listener is running
#
# Authors:
# Nicolas Gregoire <ngregoire@exaprobe.com>
# Adapted from mssql_blank_password.nasl
#
# Copyright:
# Copyright (C) 2003 Nicolas Gregoire
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10144");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Microsoft SQL TCP/IP listener is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Nicolas Gregoire");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 1433);

  script_tag(name:"summary", value:"Microsoft SQL server is running on this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("host_details.inc");
include("cpe.inc");

port = get_unknown_port( default:1433 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

payload = raw_string( 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
                      0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
                      0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
                      0x01, 0xff, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

len = strlen( payload );

# TDS7 pre-login message (http://msdn.microsoft.com/en-us/library/dd357559.aspx)
req = raw_string( 0x12, 0x01 ) +
      mkword( len + 8 ) +
      raw_string( 0x00, 0x00, 0x00, 0x00 ) +
      payload;

send( socket:soc, data:req );
buf = recv( socket:soc, length:4096 );
close( soc );

len = strlen( buf );
if( len < 18 ) exit( 0 );

res_type = ord( buf[0] );
if( res_type != 4 ) exit( 0 );

pos = 8;

if( ord( buf[ pos ] ) != 0 ) exit( 0 );

off  = getword( blob:buf, pos:pos + 1 );
blen = getword( blob:buf, pos:pos + 3 );
pos += off;

if( blen < 6 || ( pos + 6 ) > strlen( buf ) ) exit( 0 );

version = ord( buf[ pos ] ) + '.' + ord( buf[ pos + 1 ] ) + '.' + getword( blob:buf, pos:pos + 2 ) + '.' + getword( blob:buf, pos:pos + 4 );
register_service( port:port, proto:"mssql" );

register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, desc:"Microsoft SQL TCP/IP listener is running", runs_key:"windows" );

set_kb_item( name:"MS/SQLSERVER/Running", value:TRUE );
set_kb_item(name:"OpenDatabase/found", value:TRUE);

# https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary
if( version =~ "^1\.0" ) {
  releaseName = "1.0";
} else if( version =~ "^1\.1" ) {
  releaseName = "1.1";
} else if( version =~ "^4\.2" ) {
  releaseName = "4.2";
} else if( version =~ "^6\.0" ) {
  releaseName = "6.0";
} else if( version =~ "^6\.5" ) {
  releaseName = "6.5";
} else if( version =~ "^7\.0" ) {
  releaseName = "7.0";
} else if( version =~ "^8\.0" ) {
  releaseName = "2000";
} else if( version =~ "^9\.0" ) {
  releaseName = "2005";
} else if( version =~ "^10\.0" ) {
  releaseName = "2008";
} else if( version =~ "^10\.50" ) {
  releaseName = "2008 R2";
} else if( version =~ "^11\.0" ) {
  releaseName = "2012";
} else if( version =~ "^12\.0" ) {
  releaseName = "2014";
} else if( version =~ "^13\.0" ) {
  releaseName = "2016";
} else if( version =~ "^14\.0" ) {
  releaseName = "2017";
} else {
  releaseName = "unknown release name";
}

install = port + "/tcp";
set_kb_item( name:"MS/SQLSERVER/" + port + "/releasename", value:releaseName );

# TODO: We shouldn't use the release version but the release name for the CPE instead (see gb_windows_cpe_detect.nasl)
cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:sql_server:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:microsoft:sql_server';

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"Microsoft SQL Server " + releaseName,
                                          version:version,
                                          install:install,
                                          cpe:cpe ),
                                          port:port );

exit( 0 );
