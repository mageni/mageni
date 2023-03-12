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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127343");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-15 11:53:11 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-25161");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 23.0.12, 24.x < 24.0.8, 25.x < 25.0.1 Improper Access Control (GHSA-492h-596q-xr2f)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Missing rate limiting on password reset functionality allows
  sending lots of emails.");

  script_tag(name:"affected", value:"Nextcloud Server versions prior to 23.0.12, 24.x
  prior to 24.0.8 and 25.x prior to 25.0.1.");

  script_tag(name:"solution", value:"Update to version 23.0.12, 24.0.8, 25.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-492h-596q-xr2f");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "23.0.12") ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "23.0.12", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "24.0", test_version_up: "24.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "24.0.8", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "25.0", test_version_up: "25.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "25.0.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
