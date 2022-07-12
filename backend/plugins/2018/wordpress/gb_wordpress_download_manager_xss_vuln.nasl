###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_download_manager_xss_vuln.nasl 11156 2018-08-29 09:25:17Z asteins $
#
# WordPress Download Manager Plugin XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140719");
  script_version("$Revision: 11156 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-29 11:25:17 +0200 (Wed, 29 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-01-23 10:22:04 +0700 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-18032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Download Manager Plugin XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The download-manager plugin for WordPress has XSS via the id parameter in a
wpdm_generate_password action to wp-admin/admin-ajax.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Download Manager plugin 2.9.51 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9.52 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/download-manager/#developers");
  script_xref(name:"URL", value:"https://security.dxw.com/advisories/xss-download-manager/");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/download-manager/readme.txt");

if ("WordPress Download Manager" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "= ([0-9.]+) =", string: res);
  if (!isnull(vers[1])) {
    if (version_is_less(version: vers[1], test_version: "2.9.52")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.9.52");
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
