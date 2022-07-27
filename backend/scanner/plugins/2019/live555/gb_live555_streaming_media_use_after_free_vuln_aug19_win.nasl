# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112633");
  script_version("2019-08-21T12:20:27+0000");
  script_tag(name:"last_modification", value:"2019-08-21 12:20:27 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-21 11:54:11 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15232");

  script_name("Live555 Streaming Media < 2019.08.16 Use-After-Free Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("os_detection.nasl", "gb_live555_detect.nasl");
  script_mandatory_keys("Host/runs_windows", "live555_streaming_media/installed");

  script_tag(name:"summary", value:"Live555 Streaming Media is prone to a Use-After-Free vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists because GenericMediaServer::createNewClientSessionWithId
  can generate the same client session ID in succession, which is mishandled by the MPEG1or2 and Matroska file demultiplexors.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause an
  'access after delete' error.");
  script_tag(name:"affected", value:"Live555 Streaming Media before version 2019.08.16.");
  script_tag(name:"solution", value:"Update to version 2019.08.16.");

  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/changelog.txt");

  exit(0);
}

CPE = "cpe:/a:live555:streaming_media";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2019.08.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2019.08.16", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
