# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:mainwp:mainwp_child";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147256");
  script_version("2021-12-06T06:37:39+0000");
  script_tag(name:"last_modification", value:"2021-12-06 11:03:13 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-06 06:08:36 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-24877");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress MainWP Child Plugin < 4.1.8 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/mainwp-child/detected");

  script_tag(name:"summary", value:"The WordPress plugin MainWP Child is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"insight", value:"The plugin does not validate the orderby and order parameter
  before using them in a SQL statement, leading to an SQL injection exploitable by high privilege
  users such as admin when the Backup and Staging by WP Time Capsule plugin is installed.");

  script_tag(name:"affected", value:"WordPress MainWP Child plugin prior to version 4.1.8.");

  script_tag(name:"solution", value:"Update to version 4.1.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/b09fe120-ab9b-44f2-b50d-3b4b299d6d15");

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

if (version_is_less(version: version, test_version: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
