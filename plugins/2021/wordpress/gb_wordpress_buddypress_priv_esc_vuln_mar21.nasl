# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112876");
  script_version("2021-03-30T13:55:08+0000");
  script_tag(name:"last_modification", value:"2021-03-31 10:16:54 +0000 (Wed, 31 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-30 13:37:11 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-21389");

  script_name("WordPress BuddyPress Plugin 5.0.0 - 7.2.0 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/buddypress/detected");

  script_tag(name:"summary", value:"The WordPress plugin BuddyPress is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible for a non-privileged, regular user to obtain administrator rights
  by exploiting an issue in the REST API members endpoint");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to obtain administrator rights.");

  script_tag(name:"affected", value:"WordPress plugin BuddyPress version 5.0.0 through 7.2.0.");

  script_tag(name:"solution", value:"Update to version 7.2.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/buddypress/#developers");
  script_xref(name:"URL", value:"https://codex.buddypress.org/releases/version-7-2-1/");
  script_xref(name:"URL", value:"https://github.com/buddypress/BuddyPress/security/advisories/GHSA-m6j4-8r7p-wpp3");

  exit(0);
}

CPE = "cpe:/a:buddypress:buddypress";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "7.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
