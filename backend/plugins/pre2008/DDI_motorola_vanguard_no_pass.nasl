###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_motorola_vanguard_no_pass.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Motorola Vanguard with No Password
#
# Authors:
# Geoff Humes <geoff.humes@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11203");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Motorola Vanguard with No Password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Digital Defense");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Please set a strong password for this device.");

  script_tag(name:"summary", value:"This device is a Motorola Vanguard router and has
  no password set. An attacker can reconfigure
  this device without providing any authentication.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include('telnet_func.inc');

function greprecv( socket, pattern ) {

  local_var buffer, cnt, _r;

  buffer = "";
  cnt = 0;
  while( 1 ) {
    _r = recv_line( socket:socket, length:4096 );
    if( strlen( _r ) == 0 ) return FALSE;
    buffer = string( buffer, _r );
    if( ereg( pattern:pattern, string:_r ) ) return buffer;
    cnt++;
    if( cnt > 1024 ) return FALSE;
  }
}

port = get_telnet_port( default:23 );

banner = get_telnet_banner( port:port );
if ( ! banner || "OK" >!< banner ) exit( 0 );

soc = open_sock_tcp( port );

if( soc ) {

  buf = greprecv( socket:soc, pattern:".*OK.*" );
  if( ! buf ) {
    close( soc );
    exit( 0 );
  }

  send( socket:soc, data:string( "atds0\r\n" ) );
  buf = greprecv( socket:soc, pattern:".*Password.*" );

  if( ! buf ) {
    close( soc );
    exit( 0 );
  }

  send( socket:soc, data:string( "\r\n" ) );
  buf = greprecv( socket:soc, pattern:".*Logout.*" );
  if( buf ) security_message( port:port );
  close( soc );
}

exit( 99 );