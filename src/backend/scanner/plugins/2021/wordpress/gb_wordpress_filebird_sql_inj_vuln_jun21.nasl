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

CPE = "cpe:/a:ninjateam:filebird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146331");
  script_version("2021-07-20T04:25:03+0000");
  script_tag(name:"last_modification", value:"2021-07-20 10:27:54 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-20 04:08:56 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-24385");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Filebird plugin 4.7.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/filebird/detected");

  script_tag(name:"summary", value:"The WordPress plugin Filebird is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Filebird Plugin 4.7.3 introduced a SQL injection vulnerability
  as it is making SQL queries without escaping user input data from a HTTP post request. This is a
  major vulnerability as the user input is not escaped and passed directly to the get_col function
  and it allows SQL injection. The Rest API endpoint which invokes this function also does not have
  any required permissions/authentication and can be accessed by an anonymous user.");

  script_tag(name:"affected", value:"WordPress Filebird plugin version 4.7.3.");

  script_tag(name:"solution", value:"Update to version 4.7.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/filebird/#developers");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/754ac750-0262-4f65-b23e-d5523995fbfa");
  script_xref(name:"URL", value:"https://10up.com/blog/2021/security-vulnerability-filebird-wordpress-plugin/");

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

if (version == "4.7.3") {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
