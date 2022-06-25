###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_woocommerce_rce_vuln_win.nasl 13455 2019-02-05 07:38:02Z mmartin $
#
# WordPress WooCommerce Plugin RCE Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112422");
  script_version("$Revision: 13455 $");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 08:38:02 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-13 11:23:11 +0100 (Tue, 13 Nov 2018)");

  script_cve_id("CVE-2018-20714");

  script_name("WordPress WooCommerce Plugin RCE Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with the WooCommerce
  Plugin for Wordpress and is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in the way WordPress handles privileges can lead to a privilege escalation
  in the plugin. The vulnerability allows shop managers to delete certain files on the server and then to take over
  any administrator account.");

  script_tag(name:"affected", value:"WooCommerce plugin for Wordpress prior to version 3.4.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 3.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://blog.ripstech.com/2018/wordpress-design-flaw-leads-to-woocommerce-rce/");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!dir = get_app_location(cpe: CPE, port:port)) exit(0);

if(dir == "/") dir = "";

res = http_get_cache(port:port, item:dir + "/wp-content/plugins/woocommerce/readme.txt");

if("WooCommerce" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if(!isnull(vers[1]) && version_is_less(version:vers[1], test_version:"3.4.6")) {
    report = report_fixed_ver(installed_version:vers[1], fixed_version:"3.4.6", install_path:dir);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
