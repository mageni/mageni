###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_export-users-to-csv_csv_inj_vuln.nasl 14157 2019-03-13 14:44:46Z cfischer $
#
# WordPress Export Users to CSV Plugin <= 1.1.1 CSV Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.112370");
  script_version("$Revision: 14157 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:44:46 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-29 11:05:00 +0200 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-15571");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WordPress Export Users to CSV Plugin <= 1.1.1 CSV Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"Export Users to CSV plugin for WordPress is prone to a CSV injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Export Users to CSV through version 1.1.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one.

  NOTE: The plugin is not available for download anymore. Therefore no fix will be provided. It is advised to remote the plugin.");

  script_xref(name:"URL", value:"https://hackpuntes.com/cve-2018-15571-wordpress-plugin-export-users-to-csv-1-1-1-csv-injection/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45206/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/export-users-to-csv/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

CPE = "cpe:/a:wordpress:wordpress";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/export-users-to-csv/readme.txt");

if ("Export users data and metadata to a csv file." >< res && "Changelog" >< res && "A WordPress plugin that exports user data and meta data." >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less_equal(version: vers[1], test_version: "1.1.1")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "None");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
