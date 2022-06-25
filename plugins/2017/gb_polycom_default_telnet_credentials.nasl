###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_polycom_default_telnet_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Polycom HDX Default Telnet Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.112151");
  script_version("$Revision: 13624 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Polycom HDX Default Telnet Credentials");

  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-08 09:24:56 +0100 (Fri, 08 Dec 2017)");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/polycom/device/detected");

  script_xref(name:"URL", value:"https://staaldraad.github.io/2017/11/12/polycom-hdx-rce/");

  script_tag(name:"summary", value:"The Polycom device has default telnet credentials or passwordless login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to either gain direct access since no password is set or login with default credentials.");

  script_tag(name:"insight", value:"The Polycom series exposes an administrative console on port 23. This
  administrative interface is built on PSH (Polycom Shell) and allows management of
  the underlying device. By default there is no password, or the password is either
  set to 456, admin, or POLYCOM, there is no username.");

  script_tag(name:"solution", value:"It is recommended to disable the telnet access.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );

if ( "Polycom Command Shell" >< banner || "Welcome to ViewStation" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {

  if ( "Polycom Command Shell" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {

    soc = open_sock_tcp( port );
    if( ! soc ) exit( 0 );

    send( socket:soc, data: 'whoami\r\n' );
    recv = recv( socket:soc, length:2048 );
    close (soc);

    if ( "Hi, my name is" >< recv && "Here is what I know about myself" >< recv ) {
      VULN = TRUE;
      report = 'It was possible to gain access via telnet without entering any credentials.';
    }
  }

  if ( "Welcome to ViewStation" >< banner ) {
    report = 'It was possible to login via telnet using one or more of the following default credentials:\n';
    passwords = make_list( "456", "admin", "POLYCOM" );

    foreach pass ( passwords ) {
      soc = open_sock_tcp( port );
      if ( ! soc ) exit( 0 );

      recv = recv( socket:soc, length:2048 );

      if ( "Password" >< recv ) {
        send( socket:soc, data: pass + '\r\n' );
        recv = recv( socket:soc, length:1024 );

        if ( "Polycom Command Shell" >< recv ) {
          send( socket:soc, data: 'whoami\r\n' );
          recv = recv( socket:soc, length:2048 );

          if ( "Hi, my name is" >< recv && "Here is what I know about myself" >< recv ) {
            VULN = TRUE;
            report += '\nPassword: ' + pass;
          }
        }
      }
      close ( soc );
    }
  }

  if( VULN ) {
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
