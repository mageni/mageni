###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_teamspeak3_3.0.12.3.nasl 11837 2018-10-11 09:17:05Z asteins $
#
# TeamSpeak 3 Server < 3.0.12.4 Crashes On Malicious Input
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:teamspeak:teamspeak3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111111");
  script_version("$Revision: 11837 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 11:17:05 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-23 15:00:00 +0200 (Sat, 23 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("TeamSpeak 3 Server < 3.0.12.4 Crashes On Malicious Input");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_teamspeak_detect.nasl");
  script_require_ports("Services/teamspeak-serverquery", 10011);
  script_mandatory_keys("teamspeak3_server/installed");

  script_xref(name:"URL", value:"http://teamspeak.com/downloads");
  script_xref(name:"URL", value:"http://forum.teamspeak.com/threads/123250-TeamSpeak-3-Server-3-0-12-4-released");

  script_tag(name:"summary", value:"This host is running a TeamSpeak 3 server and is prone to multiple server crashes on malicious input");
  script_tag(name:"impact", value:"Exploiting this vulnerability may allow an attacker to crash the TeamSpeak 3 server on malicious input.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"TeamSpeak 3 server version prior to 3.0.12.4");
  script_tag(name:"solution", value:"Update your TeamSpeak 3 server to version 3.0.12.4 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! ver = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:ver, test_version:"3.0", test_version2:"3.0.12.3" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.0.12.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
