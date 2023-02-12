# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127306");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-20 09:26:41 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Information Disclosure Vulnerability (SA-CORE-2023-001) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Media Library module does not properly check entity access
  in some circumstances.");

  script_tag(name:"affected", value:"Drupal 8.x prior to version 9.4.10, 9.5.x prior to version
  9.5.2 and 10.x prior to version 10.0.2.");

  script_tag(name:"solution", value:"Update to version 9.4.10, 9.5.2, 10.0.2 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive (version: version, test_version_lo: "8.0.0", test_version_up: "9.4.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.4.10", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "9.5.0", test_version_up: "9.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.5.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version_lo: "10.0.0", test_version_up: "10.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.0.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
