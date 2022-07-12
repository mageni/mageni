# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:cloudways:breeze";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148097");
  script_version("2022-05-11T10:05:18+0000");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 05:54:34 +0000 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-29444");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Breeze Plugin < 2.0.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/breeze/detected");

  script_tag(name:"summary", value:"The WordPress plugin Breeze is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plugin Settings Change leading to an XSS vulnerability in
  Cloudways Breeze plugin allows users with a subscriber or higher user role to execute any of the
  wp_ajax_* actions in the class Breeze_Configuration which includes the ability to change any of
  the plugin's settings including CDN setting which could be further used for XSS attack.");

  script_tag(name:"affected", value:"WordPress Breeze plugin version 2.0.2 and prior.");

  script_tag(name:"solution", value:"Update to version 2.0.3 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/breeze/wordpress-breeze-plugin-2-0-2-plugin-settings-change-leading-to-cross-site-scripting-xss-vulnerability");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
