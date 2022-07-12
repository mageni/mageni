###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_pmpro_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# WordPress Paid Memberships Pro Plugin Multiple XSS Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112096");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-26 13:43:51 +0200 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-5532");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Paid Memberships Pro Plugin Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"Multiple cross-site scripting (XSS) vulnerabilities in the Paid Memberships Pro (PMPro) plugin for WordPress
      allow remote attackers to inject arbitrary web script or HTML via the (1) s parameter to membershiplevels.php, (2) memberslist.php,
      or (3) orders.php in adminpages/ or the (4) edit parameter to adminpages/membershiplevels.php.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Paid Memberships Pro plugin before 1.8.4.3.");

  script_tag(name:"solution", value:"Update to version 1.8.4.3 or later.");

  script_xref(name:"URL", value:"http://www.paidmembershipspro.com/2015/07/pmpro-updates-1-8-4-3-and-1-8-4-4/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/paid-memberships-pro/#developers");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/paid-memberships-pro/readme.txt");

if ("Paid Memberships Pro" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "1.8.4.3")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.8.4.3");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
