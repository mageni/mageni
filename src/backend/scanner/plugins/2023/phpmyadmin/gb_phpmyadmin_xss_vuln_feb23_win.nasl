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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127329");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-08 11:30:09 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin 4.3.x < 4.9.11, 5.2.x < 5.2.1 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user can trigger a cross-site scripting (XSS)
  attack by uploading a specially-crafted .sql file through the drag-and-drop interface.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.3.x through 4.9.10 and
  5.2.x prior to 5.2.1.");

  script_tag(name:"solution", value:"Update to version 4.9.11, 5.2.1 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2023-1/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port(cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0) ;

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version: version, test_version_lo: "4.3.0", test_version_up: "4.9.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.9.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "5.2", test_version_up: "5.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
