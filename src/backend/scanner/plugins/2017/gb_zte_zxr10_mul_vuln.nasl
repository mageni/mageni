###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zte_zxr10_mul_vuln.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# ZTE ZXR10 Router Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107254");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-10931");

  script_name("ZTE ZXR10 Router Multiple Vulnerabilities");

  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-09 10:23:00 +0200 (Thu, 09 Nov 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/zte/zxr10/detected");

  script_xref(name:"URL", value:"http://www.palada.net/index.php/2017/10/23/news-3819/");

  script_tag(name:"summary", value:"ZTE ZXR10 Router has a backdoor account with hard-coded credentials.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");
  script_tag(name:"solution", value:"Update to version 3.00.40. For more details.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1008262");
  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );

if( !banner || banner !~ "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation"  )
  exit( 0 );

creds = make_list("who;who", "zte;zte", "ncsh;ncsh");

foreach cred (creds)
{

  user_name = split(cred, sep: ";", keep: FALSE);
  name = user_name[0];
  pass = user_name[1];

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  recv = recv( socket:soc, length:2048 );

  if ( "Username:" >< recv )
  {
    send( socket:soc, data: tolower( name ) + '\r\n' );
    recv = recv( socket:soc, length:128 );

    if( "Password:" >< recv )
    {
      send( socket:soc, data: pass + '\r\n\r\n' );
      recv = recv( socket:soc, length:1024 );

      if ( !isnull(recv) )
      {
        send( socket:soc, data: '?\r\n' );
        recv = recv( socket:soc, length:1024 );

        if ( "Exec commands:" >< recv)
        {
            VULN = TRUE;
            report = 'It was possible to login via telnet using the following credentials:\n\n';
            report += 'Username: ' + name + ', Password: ' + pass;
            break;
        }
      }
    }
  }
  close( soc );
}


if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
