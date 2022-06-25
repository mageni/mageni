###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_device_default_credentials.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Lantronix Devices Default Credentials Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107329");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 18:29:24 +0200 (Thu, 12 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-14018");

  script_name("Lantronix Devices Default Credentials Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_lantronix_device_version.nasl");
  script_mandatory_keys("lantronix_device/detected");

  script_tag(name:"summary", value:"Lantronix devices have a default useraccount 'root' with password 'system' which grants
  admin rights TELNET access.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Using the command 'set privilege' followed by entering the password 'system' enables the
  attacker to gather information, change configurations, telnet to other hosts etc.");
  script_tag(name:"affected", value:"Lantronix devices with telnet access.");
  script_tag(name:"solution", value:"Consult your documentation how to change default credentials and/or disable remote access
  to the device.");

  script_xref(name:"URL", value:"https://www.lantronix.com/");

  exit(0);
}

include( "host_details.inc" );

port = get_kb_item("lantronix_device/telnet/port");
username = "root";
password = "system";

if( ! get_kb_item("lantronix_device/telnet/" + port + "/access") ) {
  exit ( 0 );
}

soc = open_sock_tcp( port );
if( ! soc )
 exit( 0 );

recv1 = recv( socket:soc, length:2048, timeout:10 );

if( "prompt for assistance" >< recv1 && "Username>" >< recv1 ) {
  send( socket:soc, data:username + '\r\n' );
  recv2 = recv( socket:soc, length:2048, timeout:10 );
  if( recv2 =~ "Local_.+>" ) {
    send( socket:soc, data:'set privileged\r\n' );
    recv3 = recv( socket:soc, length:2048, timeout:10 );
    if ( "Password>" >< recv3  ) {
      send( socket:soc, data:'system\r\n\r\n' );
      recv4 = recv( socket:soc, length:2048, timeout:10 );
      close(soc);
      if ( recv4 =~ "Local_.+>>" ) {    # The >> indicates the root shell
        vuln = TRUE;
        set_kb_item(name:"lantronix_device/telnet/" + port + "/full_access", value:TRUE );
      }
    }
  }
}

if( soc )
  close( soc );

if( vuln ) {
  report = "It was possible to gain unrestricted telnet access with username '" + username + "' and password '" + password + "'.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
