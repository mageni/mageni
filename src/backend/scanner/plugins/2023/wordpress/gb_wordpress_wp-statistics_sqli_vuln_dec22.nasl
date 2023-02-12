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

CPE = "cpe:/a:veronalabs:wp_statistics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124260");
  script_version("2023-01-26T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-24 07:25:53 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2022-4230");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin < 13.2.9 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Statistics' is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape a parameter, which could allow
  authenticated users to perform SQL Injection attacks. By default, the affected feature is
  available to users with the manage_options capability (admin+), however the plugin has a settings
  to allow low privilege users to access it as well.");

  script_tag(name:"affected", value:"WordPress WP Statistics prior to version 13.2.9.");

  script_tag(name:"solution", value:"Update to version 13.2.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a0e40cfd-b217-481c-8fc4-027a0a023312");

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

if (version_is_less(version: version, test_version: "13.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
