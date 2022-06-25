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
  script_oid("1.3.6.1.4.1.25623.1.0.112702");
  script_version("2020-02-25T10:50:36+0000");
  script_tag(name:"last_modification", value:"2020-02-25 10:50:36 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-25 10:09:00 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-9006");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Popup Builder Plugin 2.2.8 < 3.0 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("popup-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin Popup Builder is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"The plugin is vulnerable to SQL injection via PHP deserialization on
  attacker-controlled data with the attachmentUrl POST variable. This allows the creation of an arbitrary WordPress
  Administrator account, leading to possible remote code execution because administrators can run PHP code on WordPress instances.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system.");

  script_tag(name:"affected", value:"WordPress Popup Builder plugin 2.2.8 through 2.6.7.6.");

  script_tag(name:"solution", value:"Update to version 3.0 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/popup-builder/#developers");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10073");

  exit(0);
}

CPE = "cpe:/a:sygnoos:popup-builder";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "2.2.8", test_version2: "2.6.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
