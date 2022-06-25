###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_zebra_telnet_default_password.nasl 7287 2017-09-27 06:56:51Z cfischer $
#
# Zebra PrintServer Telnet Default Password
#
# Authors:
# Christian Fischer
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111061");
  script_version("$Revision: 7287 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Zebra PrintServer Telnet Default Password");
  script_tag(name:"last_modification", value:"$Date: 2017-09-27 08:56:51 +0200 (Wed, 27 Sep 2017) $");
  script_tag(name:"creation_date", value:"2015-11-25 11:00:00 +0100 (Wed, 25 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:'The remote Zebra PrintServer has a default password set.');
  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.');
  script_tag(name:"vuldetect", value:'Connect to the telnet service and try to login with a default password.');
  script_tag(name:"insight", value:'It was possible to login with default password 1234');
  script_tag(name:"solution", value:'Change/Set the password.');

  script_xref(name:"URL", value:"https://support.zebra.com/cpws/docs/znet2/ps_firm/znt2_pwd.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:1024 );

if ( "ZebraNet" >< recv || "Internal Wired PS Configuration Utility" >< recv ||
     "Type your password. Press Enter when finished." >< recv ) {

  send( socket:soc, data: '1234\r\n' );
  recv = recv( socket:soc, length:1024 );

  if( "Show Configuration/Status" >< recv || "Restore to Factory Defaults" >< recv ||
       "Specify Print Server IP Address" >< recv || "TCP Connection Configuration" >< recv ) {
    close( soc );
    security_message( port:port, data:"It was possible to login using the default password '1234'" );
    exit( 0 );
  }
}

close( soc );

exit( 99 );
