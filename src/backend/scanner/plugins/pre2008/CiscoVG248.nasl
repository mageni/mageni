###############################################################################
# OpenVAS Vulnerability Test
# $Id: CiscoVG248.nasl 13634 2019-02-13 12:06:16Z cfischer $
#
# Cisco VG248 login password is blank
#
# Authors:
# Rick McCloskey <rpm.security@gmail.com>
#
# Copyright:
# Copyright (C) 2005 Rick McCloskey
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

# Cisco VG248 with a blank password nasl script. - non intrusive
#
# Tested against production systems with positive results.
# This cisco unit does not respond to the other "Cisco with no password"
# nasl scripts.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19377");
  script_version("$Revision: 13634 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 13:06:16 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Cisco VG248 login password is blank");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Rick McCloskey");
  script_family("CISCO");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Telnet to this unit and at the configuration interface:
  Choose Configure-> and set the login and enable passwords. If
  possible, in the future do not use telnet since it is an insecure protocol.");

  script_tag(name:"impact", value:"The Cisco VG248 does not have a password set and allows direct
  access to the configuration interface. An attacker could telnet to the Cisco unit and reconfigure
  it to lock the owner out as well as completely disable the phone system.");

  script_tag(name:"summary", value:"The remote host is a Cisco VG248 with a blank password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include('telnet_func.inc');

port = get_telnet_port( default:23 );

soc = open_sock_tcp( port );
if ( ! soc ) exit( 0 );

banner = telnet_negotiate( socket:soc );
banner += line = recv_line( socket:soc, length:4096 );
n  = 0;

while( line =~ "^ ") {
  line = recv_line(socket:soc, length:4096);
  banner += line;
  n ++;
  if( n > 100 ) {
    close( soc );
    exit( 0 ); # Bad server ?
  }
}

close( soc );

if( "Main menu" >< banner && "Configure" >< banner && "Display" >< banner ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );