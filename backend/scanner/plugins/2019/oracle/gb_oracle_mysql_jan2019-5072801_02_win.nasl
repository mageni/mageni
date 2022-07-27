###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_jan2019-5072801_02_win.nasl 13237 2019-01-23 10:24:40Z asteins $
#
# Oracle MySQL 5.7.x < 5.7.24, 8.0.x < 8.0.13 Security Update (2019-5072801) Windows
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112491");
  script_version("$Revision: 13237 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 11:24:40 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-16 13:12:11 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-2434", "CVE-2019-2510", "CVE-2019-2420",
  "CVE-2019-2528", "CVE-2019-2486", "CVE-2019-2532");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL 5.7.x < 5.7.24, 8.0.x < 8.0.13 Security Update (2019-5072801) Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The attacks range in variety and difficulty. Most of them allow an attacker
  with network access via multiple protocols to compromise the MySQL Server.

  For further information refer to the official advisory via the referenced link.");
  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can result in unauthorized
  access to critical data or complete access to all MySQL Server accessible data and unauthorized ability
  to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"MySQL 5.7.24 and prior, 8.0.13 and prior on Windows.");
  script_tag(name:"solution", value:"Updates are available. Apply the necessary patch from the referenced link.");

  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixMSQL");

  exit(0);
}

CPE = "cpe:/a:oracle:mysql";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version: vers, test_version: "5.7", test_version2: "5.7.24")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "Apply the patch", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: vers, test_version: "8.0", test_version2: "8.0.13")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "Apply the patch", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
