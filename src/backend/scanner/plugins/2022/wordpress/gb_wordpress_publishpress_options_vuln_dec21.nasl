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

CPE = "cpe:/a:publishpress:publishpress_capabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147457");
  script_version("2022-01-18T09:22:40+0000");
  script_tag(name:"last_modification", value:"2022-01-19 11:07:58 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-18 08:22:27 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-25032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress PublishPress Capabilities Plugin < 2.3.1 Arbitrary Options Update Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/capability-manager-enhanced/detected");

  script_tag(name:"summary", value:"The WordPress plugin PublishPress Capabilities is prone to an
  arbitrary options update vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have authorisation and CSRF checks when
  updating the plugin's settings via the init hook, and does not ensure that the options to be
  updated belong to the plugin. As a result, unauthenticated attackers could update arbitrary blog
  options, such as the default role and make any new registered user with an administrator role.");

  script_tag(name:"affected", value:"WordPress PublishPress Capabilities version 2.3.0 and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/2f0f1a32-0c7a-48e6-8617-e0b2dcf62727");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/capability-manager-enhanced/#developers");

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

if (version_is_less(version: version, test_version: "2.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
