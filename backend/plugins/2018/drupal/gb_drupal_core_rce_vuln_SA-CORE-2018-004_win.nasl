##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_core_rce_vuln_SA-CORE-2018-004_win.nasl 12012 2018-10-22 09:20:29Z asteins $
#
# Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-004) (Windows, Version Check)
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

CPE = 'cpe:/a:drupal:drupal';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141029");
  script_version("$Revision: 12012 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 11:20:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-26 08:47:32 +0700 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-7602");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Core Critical Remote Code Execution Vulnerability (SA-CORE-2018-004) (Windows, Version Check)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists within multiple subsystems of
  Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which
  could result in the site being compromised. This vulnerability is related to SA-CORE-2018-002 (CVE-2018-7600).");

  script_tag(name:"affected", value:"Drupal 7.x and 8.x");

  script_tag(name:"solution", value:"Update to version 7.59, 8.4.8, 8.5.3 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2018-004");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE)) {
  exit(0);
}

if (!infos = get_app_version_and_location(cpe: CPE, port: port, version_regex:"^[0-9]\.[0-9.]+", exit_no_version: TRUE)) {
  exit(0);
}

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.59", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5", test_version2: "8.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
