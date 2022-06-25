##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_duplicator_rce_vuln.nasl 12355 2018-11-15 05:30:43Z ckuersteiner $
#
# WordPress Duplicator Plugin < 1.2.42 RCE Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.141688");
  script_version("$Revision: 12355 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 06:30:43 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-15 11:56:56 +0700 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-17207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator Plugin < 1.2.42 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"An issue was discovered in Snap Creek Duplicator. By accessing leftover
installer files (installer.php and installer-backup.php), an attacker can inject PHP code into wp-config.php
during the database setup step, achieving arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Snap Creek Duplicator plugin prior to version 1.2.42.");

  script_tag(name:"solution", value:"Update to version 1.2.42 or later and remove the leftover files.");

  script_xref(name:"URL", value:"https://www.synacktiv.com/ressources/advisories/WordPress_Duplicator-1.2.40-RCE.pdf");

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

urls = make_list("/installer.php", "/installer-backup.php");

foreach file (urls) {
  url = dir + file;
  res = http_get_cache(port: port, item: url);

  if ("<title>Duplicator</title>" >< res && "<label>Plugin Version:</label>" >< res) {
    vers = eregmatch(pattern: '<td class="dupx-header-version">[^v]+version: ([0-9.]+)', string: res);
    if (!isnull(vers[1])) {
      if (version_is_less(version: vers[1], test_version: "1.2.42")) {
        report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.2.42");
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
