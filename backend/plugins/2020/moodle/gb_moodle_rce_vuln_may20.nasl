# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113694");
  script_version("2020-05-25T09:40:09+0000");
  script_tag(name:"last_modification", value:"2020-05-26 09:19:23 +0000 (Tue, 26 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-25 09:31:39 +0000 (Mon, 25 May 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10738");

  script_name("Moodle < 3.5.12, 3.6.x < 3.6.10, 3.7.x < 3.7.6, 3.8.x < 3.8.3 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to create a SCORM package in such a way
  that when added to a course, it could be interacted with via web services
  in order to achieve remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"Moodle through version 3.5.11, versions 3.6.0 through 3.6.9,
  3.7.0 through 3.7.5 and 3.8.0 through 3.8.2.");

  script_tag(name:"solution", value:"Update to version 3.5.12, 3.6.10, 3.7.6 or 3.8.3 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=403513");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.5.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.10", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.7.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );