###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_count-per-day_sql_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# WordPress Count Per Day Plugin SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112095");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-26 13:42:51 +0200 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2015-5533");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Cpimt Per Day Plugin SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"An SQL injection vulnerability in counter-options.php in the Count Per Day plugin for WordPress
      allows remote authenticated administrators to execute arbitrary SQL commands via the cpd_keep_month parameter to wp-admin/options-general.php.
      NOTE: this can be leveraged using CSRF to allow remote attackers to execute arbitrary SQL commands.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Count Per Day plugin before 3.4.1.");

  script_tag(name:"solution", value:"Update to version 3.4.1 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/1190683/count-per-day");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132811/WordPress-Count-Per-Day-3.4-SQL-Injection.html");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/count-per-day/readme.txt");

if ("Count per Day" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "3.4.1")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "3.4.1");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
