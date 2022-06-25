###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_accelerated-mobile-pages_code_injection_vuln.nasl 12418 2018-11-19 13:37:19Z asteins $
#
# WordPress AMP for WP - Accelerated Mobile Pages Plugin < 0.9.97.20 Unauthorized Code Injection Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112432");
  script_version("$Revision: 12418 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:37:19 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-13 12:21:00 +0100 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress AMP for WP - Accelerated Mobile Pages Plugin < 0.9.97.20 Unauthorized Code Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress Accelerated Mobile Pages plugin is prone to a code injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"WordPress Accelerated Mobile Pages plugin before version 0.9.97.20.");
  script_tag(name:"solution", value:"Update the plugin to version 0.9.97.20 or later.");

  script_xref(name:"URL", value:"https://www.webarxsecurity.com/amp-plugin-vulnerability/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/accelerated-mobile-pages/#developers");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

CPE = "cpe:/a:wordpress:wordpress";

if (!port = get_app_port(cpe: CPE)) exit(0);
if (!dir = get_app_location(cpe: CPE, port: port)) exit(0);

if (dir == "/") dir = "";

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/accelerated-mobile-pages/readme.txt");

if ("Accelerated Mobile Pages ===" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "0.9.97.20")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "0.9.97.20");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
