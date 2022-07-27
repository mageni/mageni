# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117712");
  script_version("2021-10-13T08:01:25+0000");
  script_cve_id("CVE-2018-15715");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2021-10-12 12:18:21 +0000 (Tue, 12 Oct 2021)");
  script_name("Zoom Client Unauthorized Message Processing Vulnerability (ZSB-18001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl", "gb_zoom_client_smb_login_detect.nasl",
                      "gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/detected");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2018-40");

  script_tag(name:"summary", value:"Zoom Client is prone to an unauthorization message processing
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the Zoom client could allow a remote,
  unauthenticated attacker to control meeting functionality such as ejecting meeting participants,
  sending chat messages, and controlling participant microphone muting. If the attacker was also a
  valid participant in the meeting and another participant was sharing their desktop screen, the
  attacker could also take control of that participant's keyboard and mouse.

  The vulnerability is due to the fact that Zoom's internal messaging pump dispatched both client
  User Datagram Protocol (UDP) and server Transmission Control Protocol (TCP) messages to the same
  message handler. An attacker can exploit this vulnerability to craft and send UDP packets which
  get interpreted as messages processed from the trusted TCP channel used by authorized Zoom
  servers.");

  script_tag(name:"affected", value:"The Zoom client:

  - before version 4.1.34460.1105 on Windows

  - before version 4.1.34475.1105 on Mac OS X

  - before version 2.5.146186.1130 on Linux");

  script_tag(name:"solution", value:"Update the:

  - Microsoft Windows client to version 4.1.34460.1105 or later

  - Mac client to version 4.1.34475.1105 or later

  - Linux client to version 2.5.146186.1130 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( get_kb_item( "zoom/client/mac/detected" ) )
  check = "4.1.34475.1105";
else if( get_kb_item( "zoom/client/win/detected" ) )
  check = "4.1.34460.1105";
else
  check = "2.5.146186.1130";

if( version_is_less( version:vers, test_version:check ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:check, install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );