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
  script_oid("1.3.6.1.4.1.25623.1.0.112593");
  script_version("2019-06-03T15:25:55+0000");
  script_tag(name:"last_modification", value:"2019-06-03 15:25:55 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-03 17:21:00 +0200 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-10752");

  script_name("Serendipity <= 2.0.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_mandatory_keys("Serendipity/installed");

  script_tag(name:"summary", value:"Serendipity is prone to sql injection and remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - serendipity_moveMediaDirectory in Serendipity allows remote attackers to upload and execute arbitrary PHP code because
  it mishandles an extensionless filename during a rename

  - a possible SQL injection for entry category assignment

  - possible SQL injection for removing&adding a plugin

  Additional hardening to prevent Server Side Request Forgery (SSRF) was added as well.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary
  PHP code in the context of the application.");

  script_tag(name:"affected", value:"Serendipity through version 2.0.3.");

  script_tag(name:"solution", value:"Update to version 2.0.4 or later.");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2016/serendipity-from-file-upload-to-code-execution/");
  script_xref(name:"URL", value:"https://github.com/s9y/Serendipity/releases/tag/2.0.4");

  exit(0);
}

CPE = "cpe:/a:s9y:serendipity";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "2.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.4", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
