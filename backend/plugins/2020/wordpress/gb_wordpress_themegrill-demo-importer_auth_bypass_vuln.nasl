# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112700");
  script_version("2020-02-19T11:06:31+0000");
  script_tag(name:"last_modification", value:"2020-02-19 11:06:31 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 10:52:00 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ThemeGrill Demo Importer Plugin 1.3.4 < 1.6.2 Authentication Bypass and Database Wipe Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("themegrill-demo-importer/detected");

  script_tag(name:"summary", value:"A critical vulnerability in the WordPress plugin ThemeGrill Demo Importer
  allows any unauthenticated user to wipe the entire database to its default state after
  which they are automatically logged in as an administrator.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to bypass authentication
  and wipe the entire underlying WordPress database.");

  script_tag(name:"affected", value:"WordPress ThemeGrill Demo Importer plugin versions 1.3.4 through 1.6.1.");

  script_tag(name:"solution", value:"Update to version 1.6.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/themegrill-demo-importer/#developers");
  script_xref(name:"URL", value:"https://www.webarxsecurity.com/critical-issue-in-themegrill-demo-importer/");

  exit(0);
}

CPE = "cpe:/a:themegrill:themegrill-demo-importer";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.3.4", test_version2: "1.6.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
