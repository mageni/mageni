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

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127311");
  script_version("2023-01-26T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 08:01:26 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:C/A:C");

  script_cve_id("CVE-2023-0284");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 2.0.x < 2.0.0p33, 2.1.x < 2.1.0p20 Improper User ID's Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to an improper user id's validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The User IDs synced from an LDAP connection are not properly
  sanitized. The allowed characters for LDAP users user IDs are not restricted in the same way as local user IDs.");

  script_tag(name:"affected", value:"Checkmk versions 1.6.0 (EOL), 2.0.x prior to 2.0.0p33 and 2.1.x
  prior to 2.1.0p20.");

  script_tag(name:"solution", value:"Update to version 2.0.0p33, 2.1.0p20 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/de/werk/15181");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if(version_is_equal( version: version, test_version: "1.6.0" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p33", install_path: location );
    security_message( port: port, data: report );
    exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p33" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0p33", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0p20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.0p20", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
