###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_woocommerce-products-filter_mult_vuln.nasl 12333 2018-11-13 11:38:47Z asteins $
#
# WordPress WOOF - Products Filter for WooCommerce Plugin < 1.2.2.0 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112424");
  script_version("$Revision: 12333 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 12:38:47 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-13 12:21:00 +0100 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-8710", "CVE-2018-8711");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WOOF - Products Filter for WooCommerce Plugin < 1.2.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress WOOF - Products Filter for WooCommerce plugin is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"WordPress WOOF - Products Filter for WooCommerce plugin before version 1.2.2.0.");
  script_tag(name:"solution", value:"Update the plugin to version 1.2.2.0 or later.");

  script_xref(name:"URL", value:"https://www.woocommerce-filter.com/update-woocommerce-products-filter-v-2-2-0/");
  script_xref(name:"URL", value:"https://sec-consult.com/en/blog/advisories/arbitrary-shortcode-execution-local-file-inclusion-in-woof-pluginus-net/index.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/woocommerce-products-filter/#developers");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/woocommerce-products-filter/readme.txt");

if ("=== WOOF - Products Filter for WooCommerce ===" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "1.2.2.0")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.2.2.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
