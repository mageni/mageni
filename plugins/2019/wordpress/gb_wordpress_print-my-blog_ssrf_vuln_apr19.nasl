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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112570");
  script_version("2019-05-07T08:07:52+0000");
  script_tag(name:"last_modification", value:"2019-05-07 08:07:52 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-29 13:53:00 +0200 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-11565");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Print My Blog Plugin < 1.6.7 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Print My Blog is prone to an SSRF vulnerability.");
  script_tag(name:"insight", value:"The wp_remote_get()[2] function is called with an attacker
  controllable URL, resulting in unauthenticated SSRF. By setting up a malicious web server,
  the SSRF can be further chained to launch a reflected XSS attack.");
  script_tag(name:"affected", value:"WordPress Print My Blog plugin before version 1.6.7.");
  script_tag(name:"solution", value:"Update to version 1.6.7 or later.");

  script_xref(name:"URL", value:"http://dumpco.re/bugs/wp-plugin-print-my-blog-ssrf");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/print-my-blog/#developers");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/print-my-blog/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== Print My Blog ===" >< res && "Changelog" >< res) {

  vers = eregmatch( pattern: "= ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "1.6.7")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.6.7", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
