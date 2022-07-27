# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:wordpress:wordpress';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140174");
  script_version("2019-06-11T02:01:27+0000");
  script_tag(name:"last_modification", value:"2019-06-11 02:01:27 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 01:58:42 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-12566");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin <= 12.6.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WP Statistics plugin for WordPress has a stored XSS in
  includes/class-wp-statistics-pages.php. This is related to an account with the Editor role creating a post with
  a title that contains JavaScript, to attack an admin user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WP Statistics plugin 12.6.5 and prior.");

  script_tag(name:"solution", value:"Update to version 12.7 or later.");

  script_xref(name:"URL", value:"https://github.com/wp-statistics/wp-statistics/issues/271");

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

url = dir + "/wp-content/plugins/wp-statistics/readme.txt";
res = http_get_cache(port: port, item: url);

if ("WP Statistics" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    if (version_is_less_equal(version: vers[1], test_version: "12.6.5")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "12.7", file_checked: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
