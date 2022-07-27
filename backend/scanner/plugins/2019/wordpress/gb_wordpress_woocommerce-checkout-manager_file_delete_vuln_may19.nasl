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
  script_oid("1.3.6.1.4.1.25623.1.0.112575");
  script_version("2019-05-08T13:35:44+0000");
  script_tag(name:"last_modification", value:"2019-05-08 13:35:44 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-08 15:30:00 +0200 (Wed, 08 May 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2019-11807");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WooCommerce Checkout Plugin < 4.3 Unauthenticated Media Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin WooCommerce Checkout is prone to an unauthenticated media deletion vulnerability.");
  script_tag(name:"insight", value:"The plugin allows media deletion via the wp-admin/admin-ajax.php?action=update_attachment_wccm wccm_default_keys_load
  parameter because of a nopriv_ registration and a lack of capabilities checks.");
  script_tag(name:"affected", value:"WordPress WooCommerce Checkout plugin before version 4.3.");
  script_tag(name:"solution", value:"Update to version 4.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2019/05/unauthenticated-media-deletion-vulnerability-patched-in-woocommerce-checkout-manager-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/woocommerce-checkout-manager/#developers");

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

url = dir + "/wp-content/plugins/woocommerce-checkout-manager/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== WooCommerce Checkout Manager ===" >< res && "Changelog" >< res) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "4.3")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "4.3", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
