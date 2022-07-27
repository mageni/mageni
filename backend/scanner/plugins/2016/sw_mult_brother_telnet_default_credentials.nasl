###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_mult_brother_telnet_default_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Brother Multiple Devices Telnet Default Password
#
# Authors:
# Christian Fischer
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.111092");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Brother Multiple Devices Telnet Default Password");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-26 18:12:12 +0100 (Sat, 26 Mar 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/brother/device/detected");

  script_tag(name:"summary", value:"The remote Brother Device has a default password set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with a default password.");

  script_tag(name:"insight", value:"It was possible to login with default password 'access' or without any password.");

  script_tag(name:"solution", value:"Change/Set the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner( port:port );
if(!banner || "Welcome. Type <return>, enter password at # prompt" >!< banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data: '\r\naccess\r\n\r\n' );
recv = recv( socket:soc, length:512 );

send( socket:soc, data: '\r\n' );
recv = recv( socket:soc, length:512 );

send( socket:soc, data: 'show version\r\n' );
recv = recv( socket:soc, length:512 );
close( soc );

if( "Brother" >< recv ) {
  security_message( port:port, data:'It was possible to login using the default password "access" or no password and any username.' );
  exit( 0 );
}

exit( 99 );