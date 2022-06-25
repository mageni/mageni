###############################################################################
# OpenVAS Vulnerability Test
# $Id: nortel_pwdless1.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Nortel Networks passwordless router (manager level)
#
# Authors:
# Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2000 Victor Kirhenshtein
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
  script_oid("1.3.6.1.4.1.25623.1.0.10528");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel Networks passwordless router (manager level)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Victor Kirhenshtein");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/nortel_bay_networks/device/detected");

  script_tag(name:"solution", value:"Telnet to this router and set a password immediately.");

  script_tag(name:"summary", value:"The remote Nortel Networks (former Bay Networks) router has
  no password for the manager account.");

  script_tag(name:"impact", value:"An attacker could telnet to the router and reconfigure it to lock
  you out of it. This could prevent you from using your Internet connection.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner || "Bay Networks" >!< banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

buf = telnet_negotiate( socket:soc );
if( "Bay Networks" >< buf ) {
  if( "Login:" >< buf ) {
    data = string( "Manager\r\n" );
    send( socket:soc, data:data );
    buf2 = recv( socket:soc, length:1024 );
    close( soc );
    if( "$" >< buf2 ) {
      security_message( port:port );
      exit( 0 );
    }
    exit( 99 );
  }
}

close( soc );

exit( 99 );