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
  script_oid("1.3.6.1.4.1.25623.1.0.112705");
  script_version("2020-02-28T13:16:52+0000");
  script_tag(name:"last_modification", value:"2020-02-28 13:16:52 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-28 12:43:11 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-5244");

  script_name("WordPress BuddyPress Plugin < 5.1.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("buddypress/detected");

  script_tag(name:"summary", value:"The WordPress plugin BuddyPress is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Requests to a certain REST API endpoint can result in private user data getting exposed.
  Authentication is not needed.");

  script_tag(name:"impact", value:"Successful exploitation could result in the exposure of private data.");

  script_tag(name:"affected", value:"WordPress plugin BuddyPress before version 5.1.2.");

  script_tag(name:"solution", value:"Update to version 5.1.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/buddypress/#developers");
  script_xref(name:"URL", value:"https://buddypress.org/2020/01/buddypress-5-1-2/");
  script_xref(name:"URL", value:"https://github.com/buddypress/BuddyPress/security/advisories/GHSA-3j78-7m59-r7gv");

  exit(0);
}

CPE = "cpe:/a:buddypress:buddypress";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.1.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
