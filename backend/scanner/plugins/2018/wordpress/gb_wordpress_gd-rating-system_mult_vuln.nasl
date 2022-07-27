###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_gd-rating-system_mult_vuln.nasl 12368 2018-11-16 03:53:29Z ckuersteiner $
#
# WordPress GD Rating System Plugin Multiple Vulnerabilities
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112180");
  script_version("$Revision: 12368 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 04:53:29 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-09 09:30:00 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-5286", "CVE-2018-5287", "CVE-2018-5288", "CVE-2018-5289", "CVE-2018-5290",
                "CVE-2018-5291", "CVE-2018-5292", "CVE-2018-5293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GD Rating System Plugin Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"GD Rating System plugin for WordPress is prone to multiple cross-site
scripting (XSS) and directory traversal / local file inclusion vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress GD Rating System plugin up to and including version 2.3.");

  script_tag(name:"solution", value:"Update to version 2.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/d4wner/Vulnerabilities-Report/blob/master/gd-rating-system.md");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/gd-rating-system/readme.txt");

if ("GD Rating System" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Version: ([0-9.]+)", string: res);

  if (!isnull(vers[1]) && version_is_less_equal(version: vers[1], test_version: "2.3")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.3.2");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
