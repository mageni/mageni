# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:mndpsingh287:wp-file-manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144536");
  script_version("2020-09-09T04:55:19+0000");
  script_tag(name:"last_modification", value:"2020-09-09 09:59:16 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 04:24:42 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress File Manager Plugin 6.0 - 6.8 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin File Manager is prone to an unauthenticated remote code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The WP File Manager plugin contains the elFinder library which is used in a
  way that introduced a remote code execution vulnerability which is used in active attacks.");

  script_tag(name:"impact", value:"An unauthenticated attacker may upload a shell and execute arbitrary commands.");

  script_tag(name:"affected", value:"WordPress File Manager plugin versions 6.0 - 6.8.");

  script_tag(name:"solution", value:"Update to version 6.9 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/");

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

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
