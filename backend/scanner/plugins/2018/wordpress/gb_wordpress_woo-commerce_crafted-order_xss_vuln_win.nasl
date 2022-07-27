###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_woo-commerce_crafted-order_xss_vuln_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# WordPress WooCommerce Plugin Crafted Order XSS Vulnerability (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812809");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2015-2329");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 16:53:22 +0530 (Tue, 20 Feb 2018)");
  script_name("WordPress WooCommerce Plugin Crafted Order XSS Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with WooCommerce
  Plugin for Wordpress and is prone to Cross-site Scripting Vulnerability.");

  script_tag(name:"vuldetect", value:"Get the wordpress installation
  confirmation with the help of the detect NVT and check if the WooCommerce
  is installed and is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to input validation
  error in the order parameter of the order page.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an
  attackers to inject arbitrary web script or HTML via a crafted order.");

  script_tag(name:"affected", value:"WooCommerce plugin for Wordpress versions  prior to 2.3.6 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 2.3.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-15-020");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/woocommerce/woocommerce/master/CHANGELOG.txt");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");
  script_xref(name:"URL", value:"https://woocommerce.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!wooport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe: CPE, port:wooport)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

res = http_get_cache(port:wooport, item: dir + "/wp-content/plugins/woocommerce/readme.txt");
if("WooCommerce" >< res && "Changelog" >< res)
{
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);
  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "2.3.6"))
  {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.3.6", install_path:dir);
    security_message(port:wooport, data: report);
    exit(0);
  }
}
exit(0);
