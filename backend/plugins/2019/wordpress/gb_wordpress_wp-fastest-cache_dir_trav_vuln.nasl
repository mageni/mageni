# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142691");
  script_version("2019-08-01T08:06:05+0000");
  script_tag(name:"last_modification", value:"2019-08-01 08:06:05 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 08:01:51 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-13635");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 0.8.9.6 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress Fastest Cache plugin is prone to a directory traversal
  vulnerability.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin version 0.8.9.5 and prior.");

  script_tag(name:"solution", value:"Update to version 0.8.9.6 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/153821/WordPress-WP-Fastest-Cache-0.8.9.5-Directory-Traversal.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-fastest-cache/#developers");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-fastest-cache/readme.txt";
res = http_get_cache(port: port, item: url);

if ("=== WP Fastest Cache ===" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (vers[1] && version_is_less(version: vers[1], test_version: "0.8.9.6")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "0.8.9.6", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
