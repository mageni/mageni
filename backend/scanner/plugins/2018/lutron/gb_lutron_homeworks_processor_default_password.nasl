###############################################################################
# OpenVAS Vulnerability Test
#
# Lutron Devices Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113206");
  script_version("2019-05-09T15:03:03+0000");
  script_tag(name:"last_modification", value:"2019-05-09 15:03:03 +0000 (Thu, 09 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-05 12:36:33 +0200 (Tue, 05 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-11629", "CVE-2018-11681", "CVE-2018-11682");

  script_name("Lutron Devices Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"Lutron devices have default admin credentials that cannot be changed.");

  script_tag(name:"vuldetect", value:"Tries to login with the default credentials and reports if it was
  successful.");

  script_tag(name:"insight", value:"The devices each use one of the two following (user:password) pairs:

  - lutron:integration

  - nwk:nwk2");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain admin access to the
  target system.");

  script_tag(name:"affected", value:"The vulnerability affects multiple Lutron devices.");

  script_tag(name:"solution", value:"No known solution is available as of 09th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"http://sadfud.me/explotos/CVE-2018-11629");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default: 23 );
if( get_kb_item( "telnet/" + port + "/no_login_banner" ) )
  exit( 0 );

creds = make_array( "lutron", "integration",
                    "nwk", "nwk2" );

foreach login( keys( creds ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  recv = recv( socket: soc, length: 2048 );
  if( ! recv )
    continue;

  if( "login:" >< tolower( recv ) ) {
    send( socket: soc, data: login + '\r\n' );
    recv = recv( socket: soc, length: 256 );

    if( recv && "password:" >< tolower( recv ) ) {
      send( socket: soc, data: creds[login] + '\r\n' );
      recv = recv( socket: soc, length: 2048 );

      VULN = FALSE;
      if( "QNET>" >< recv)
        VULN = TRUE;

      send( socket: soc, data: '?HELP,#ETHERNET\r\n' );
      recv = recv( socket: soc, length: 2048 );

      if( "Configures the IP" >< recv || VULN ) {
        report = 'It was possible to gain administrative access using the credentials: "' + login + '":"' + creds[login] + '".';
        security_message( data: report, port: port );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
