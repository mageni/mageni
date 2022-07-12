###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_ultimate-form-builder-lite_sql_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# WordPress Ultimate Form Builder Lite Plugin SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112101");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-03 14:15:51 +0200 (Fri, 03 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-15919");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Form Builder Lite Plugin SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The ultimate-form-builder-lite plugin has SQL Injection, with resultant PHP Object Injection, via wp-admin/admin-ajax.php.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Ultimate Form Builder Lite plugin before 1.3.7.");

  script_tag(name:"solution", value:"Update to version 1.3.7 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8935");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-form-builder-lite/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2017/10/zero-day-vulnerability-ultimate-form-builder-lite/");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/ultimate-form-builder-lite/readme.txt");

if ("Ultimate Form Builder Lite" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "1.3.7")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.3.7");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
