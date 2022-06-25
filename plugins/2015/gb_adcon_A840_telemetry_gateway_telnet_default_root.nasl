###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adcon_A840_telemetry_gateway_telnet_default_root.nasl 11536 2018-09-21 19:44:30Z cfischer $
#
# Adcon A840 Telemetry Gateway Default root Telnet Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105492");
  script_version("$Revision: 11536 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Adcon A840 Telemetry Gateway Default root Telnet Credential");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 21:44:30 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-12-17 17:26:56 +0100 (Thu, 17 Dec 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks");
  script_dependencies("gb_adcon_A840_telemetry_gateway_telnet_detect.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:'The remote Adcon A840 Telemetry Gateway has default credentials set.');
  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain  access to sensitive information or modify system configuration.');
  script_tag(name:"vuldetect", value:'Connect to the telnet service and try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials of root:840sw');
  script_tag(name:"solution", value:'Change/Set the password.');

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");
  script_mandatory_keys("tg_A840/telnet/port");

  exit(0);
}

include("telnet_func.inc");

if( ! port = get_kb_item("tg_A840/telnet/port") ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = telnet_negotiate( socket:soc );

if( "a840 login:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: 'root\r\n' );
sleep( 3 );
recv = recv( socket:soc, length:128 );

if( "Password:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: '840sw\r\n' );
sleep(3);
recv = recv( socket:soc, length:1024 );

if( ( recv && ">" >< recv ) && "Login incorrect" >!< recv )
{
  send( socket:soc, data: 'uname -a\r\n' );
  recv = recv( socket:soc, length:128 );

  if( recv =~ '^Linux a840' )
  {
    security_message( port:port );
    close( soc );
    exit( 0 );
  }
}

if( soc ) close( soc );

exit( 99 );

