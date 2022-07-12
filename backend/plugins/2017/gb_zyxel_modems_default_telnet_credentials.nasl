###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_modems_default_telnet_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# ZyXEL Modems Backup Telnet Account and Default Root Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.112100");
  script_version("$Revision: 13624 $");
  script_cve_id("CVE-2016-10401");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("ZyXEL Modems Backup Telnet Account and Default Root Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-02 09:19:00 +0200 (Thu, 02 Nov 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/zyxel/modem/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43105/");
  script_xref(name:"URL", value:"https://forum.openwrt.org/viewtopic.php?id=62266");
  script_xref(name:"URL", value:"https://thehackernews.com/2017/11/mirai-botnet-zyxel.html");
  script_xref(name:"URL", value:"https://www.reddit.com/r/centurylink/comments/5lt07r/zyxel_c1100z_default_lanside_telnet_login/");

  script_tag(name:"summary", value:"ZyXEL PK5001Z and C1100Z modems have default root credentials set and a backdoor account with hard-coded credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"solution", value:"It is recommended to disable the telnet access and change the backup and default credentials.");

  script_tag(name:"insight", value:"In February 2018 it was discovered that this vulnerability is being exploited by the
  'DoubleDoor' Internet of Things (IoT) Botnet.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner )
  exit( 0 );

if( "PK5001Z login:" >< banner || "BCM963268 Broadband Router" >< banner ) found = TRUE;

if ( found ) {

  login = "admin";
  passwords = make_list( "CenturyL1nk", "CentryL1nk", "QwestM0dem" );
  root_pass = "zyad5001";

  report = 'The following issues have been found:\n';

  foreach pass( passwords ) {
    soc = open_sock_tcp( port );
    if( ! soc ) continue;

    recv = recv( socket:soc, length:2048 );

    if ( "PK5001Z login:" >< recv || "Login:" >< recv ) {
      send( socket:soc, data: tolower( login ) + '\r\n' );
      recv = recv( socket:soc, length:128 );

      if( "Password:" >< recv ) {
        send( socket:soc, data: pass + '\r\n\r\n' );
        recv = recv( socket:soc, length:1024 );

        send( socket:soc, data: 'whoami\r\n' );
        recv = recv( socket:soc, length:1024 );

        if( recv  =~ "admin" ) {
          VULN = TRUE;
          report += '\n\nIt was possible to login via telnet using the following backup credentials:\n';
          report += 'Login: ' + login + ', Password: ' + pass;
        }

        send( socket:soc, data: 'su\r\n' );
        recv = recv( socket:soc, length:1024 );

        send( socket:soc, data: root_pass + '\r\n' );
        recv = recv( socket:soc, length:1024 );

        send( socket:soc, data: 'cat /etc/zyfwinfo\r\n' );
        recv = recv( socket:soc, length:1024 );

        if( recv =~ "ZyXEL Communications Corp." ) {
          VULN = TRUE;
          report += '\n\nIt was possible to escalate to root privileges with the following root password: ' + root_pass;
        }
      }
    }

    close( soc );
  }

  if( VULN ) {
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    exit( 99 );
  }
}

exit( 0 );