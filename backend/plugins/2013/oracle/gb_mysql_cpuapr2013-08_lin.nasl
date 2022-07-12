# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809814");
  script_version("2021-02-09T10:19:40+0000");
  script_tag(name:"last_modification", value:"2021-02-10 11:15:07 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2016-11-18 15:18:27 +0530 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"1.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2013-1502");

  script_bugtraq_id(59239);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL 5.5 <= 5.5.30 / 5.6 <= 5.6.9 Security Update (cpuapr2013) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unspecified error exists in the MySQL Server component via
  unknown vectors related to Server Partition.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to affect availability.");

  script_tag(name:"affected", value:"Oracle MySQL 5.5 versions 5.5.30 and prior, 5.6.9 and prior.");

  script_tag(name:"solution", value:"Update to version 5.5.31, 5.6.10 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2013.html#AppendixMSQL");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.6", test_version2: "5.6.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
