###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_live_chat_support_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# WordPress WP Live Chat Support Plugin XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112066");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-06 09:21:51 +0200 (Fri, 06 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-2187");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Live Chat Support Plugin XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress plugin WP Live Chat Support is vulnerable to cross-site scripting (XSS) resulting in
attackers being able to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress WP Live Chat Support plugin version 7.0.06 and prior.");

  script_tag(name:"solution", value:"Update to version 7.0.07 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-live-chat-support/#developers");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/wp-live-chat-support/readme.txt");

if ("WP Live Chat Support" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  # Stable tag is "trunk", get the latest Changelog version
  if (isnull(vers[1])) {
    limit = eregmatch(pattern: "\=\= Changelog \=\=(.*)\*", string: res);
    vers = eregmatch(pattern: "\= ([0-9.]+)", string: limit[1]);
  }

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "7.0.07")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "7.0.07");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
