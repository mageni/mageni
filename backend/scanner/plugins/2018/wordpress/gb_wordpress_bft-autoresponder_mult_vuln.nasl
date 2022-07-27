###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_bft-autoresponder_mult_vuln.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# WordPress Arigato Autoresponder and Newsletter Plugin < 2.5.2 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.112446");
  script_version("$Revision: 12938 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-04 10:37:00 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-1002000", "CVE-2018-1002001", "CVE-2018-1002002", "CVE-2018-1002003",
                "CVE-2018-1002004", "CVE-2018-1002005", "CVE-2018-1002006", "CVE-2018-1002007",
                "CVE-2018-1002008", "CVE-2018-1002009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Arigato Autoresponder and Newsletter Plugin < 2.5.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress Arigato Autoresponder and Newsletter plugin is prone to
  blind SQL injection and multiple reflected XSS vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"WordPress Arigato Autoresponder and Newsletter plugin through version 2.5.1.8.");
  script_tag(name:"solution", value:"Update the plugin to version 2.5.2 or later.");

  script_xref(name:"URL", value:"http://www.vapidlabs.com/advisory.php?v=203");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/bft-autoresponder/#developers");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/bft-autoresponder/readme.txt");

if ("=== Arigato Autoresponder and Newsletter ===" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "2.5.2")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.5.2");
    security_message(port: port, data: report);
    exit(0);
  } else {
    # In case of 'Stable tag: trunk' try to get the version from another file
    res = http_get_cache(port: port, item: dir + "/wp-content/plugins/bft-autoresponder/bft-autoresponder.php");

    if ("Plugin Name: Arigato Autoresponder and Newsletter" >< res) {

      vers = eregmatch(pattern: "Version: ([0-9.]+)", string: res);

      if (!isnull(vers[1]) && version_is_less(version: vers[1], test_version: "2.5.2")) {
        report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.5.2");
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
