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
  script_oid("1.3.6.1.4.1.25623.1.0.112703");
  script_version("2020-02-25T10:50:36+0000");
  script_tag(name:"last_modification", value:"2020-02-25 10:50:36 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-25 10:09:00 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-9043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress wpCentral Plugin < 1.5.1 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wp-central/detected");

  script_tag(name:"summary", value:"The WordPress plugin wpCentral is prone to an improper access control vulnerability.");

  script_tag(name:"insight", value:"The flaw allows anybody to escalate their privileges to those of an administrator,
  as long as subscriber-level registration was enabled on a given WordPress site with the vulnerable plugin installed.

  The flaw also allowed for remote control of the site via the wpCentral administrative dashboard.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow an authenticated remote attacker
  to escalate his privileges to those of an administrator and remotely control the affected site.");

  script_tag(name:"affected", value:"WordPress wpCentral plugin before version 1.5.1.");

  script_tag(name:"solution", value:"Update to version 1.5.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-central/#developers");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10074");

  exit(0);
}

CPE = "cpe:/a:wpcentral:wpcentral";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
