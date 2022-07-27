# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113650");
  script_version("2020-03-06T09:53:13+0000");
  script_tag(name:"last_modification", value:"2020-03-09 11:53:43 +0000 (Mon, 09 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-06 09:07:30 +0000 (Fri, 06 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-1888", "CVE-2020-1892", "CVE-2020-1893");

  script_name("HHVM Multiple Vulnerabilities (March 2020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hhvm_detect.nasl");
  script_mandatory_keys("HHVM/detected");

  script_tag(name:"summary", value:"HHVM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Insufficient boundary checks when decoding JSON in
    handleBackslash allow reading out of bounds memory.

  - Insufficient boundary checks when decoding JSON in
    JSON_parser allow reading out of bounds memory.

  - Insufficient boundary checks when decoding JSON in
    TryParse allow reading out of bounds memory.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  cause a denial of service or read sensitive information.");

  script_tag(name:"affected", value:"HHVM through version 4.8.6, versions 4.9.0 through 4.32.0,
  4.33.0 through 4.38.0, 4.39.0, 4.40.0, 4.41.0, 4.42.0,
  4.43.0, 4.44.0 and 4.45.0.");

  script_tag(name:"solution", value:"Update to version 4.8.7, 4.32.1, 4.38.1, 4.39.1, 4.40.1,
  4.41.1, 4.42.1, 4.43.1, 4.44.1 or 4.45.1 respectively.");

  script_xref(name:"URL", value:"https://hhvm.com/blog/2020/02/20/security-update.html");

  exit(0);
}

CPE = "cpe:/a:facebook:hhvm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.8.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.8.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.9.0", test_version2: "4.32.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.32.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.33.0", test_version2: "4.38.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.38.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.39.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.39.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.40.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.40.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.41.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.41.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.42.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.42.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.43.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.43.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.44.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.44.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "4.45.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.45.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
