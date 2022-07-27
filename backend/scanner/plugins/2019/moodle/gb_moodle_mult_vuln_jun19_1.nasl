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
  script_oid("1.3.6.1.4.1.25623.1.0.113419");
  script_version("2019-07-01T11:42:50+0000");
  script_tag(name:"last_modification", value:"2019-07-01 11:42:50 +0000 (Mon, 01 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-01 13:32:47 +0000 (Mon, 01 Jul 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10133", "CVE-2019-10134");

  script_name("Moodle <= 3.1.17, 3.4.x <= 3.4.8, 3.5.x <= 3.5.5, 3.6.x <= 3.6.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - The form to upload cohorts contains a redirect field which is not restricted to internal URLs

  - The size of users' private file uploads via email are not correctly checked,
    so their quota allowance could be exceeded.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to redirect a victim to a malicious site or
  upload bigger files than allowed.");
  script_tag(name:"affected", value:"Moodle through version 3.1.17, versions 3.4.0 through 3.4.8, 3.5.0 through 3.5.5
  and 3.6.0 through 3.6.3.");
  script_tag(name:"solution", value:"Update to version 3.1.18, 3.4.9, 3.5.6 or 3.6.4 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=386523");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=386524");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.1.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.18", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.6", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
