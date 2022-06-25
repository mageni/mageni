# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804781");
  script_version("2021-02-09T12:26:32+0000");
  script_tag(name:"last_modification", value:"2021-02-10 11:15:07 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-10-20 13:30:37 +0530 (Mon, 20 Oct 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-6507", "CVE-2014-6491", "CVE-2014-6500", "CVE-2014-6469", "CVE-2014-6555",
                "CVE-2014-6559", "CVE-2014-6494", "CVE-2014-6496", "CVE-2014-6464");

  script_bugtraq_id(70487, 70530, 70550, 70478, 70469, 70497, 70444, 70446, 70451);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL <= 5.5.39 / 5.6 <= 5.6.20 Security Update (cpuoct2014) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server component via unknown vectors
  related to C API SSL CERTIFICATE HANDLING, SERVER:DML, SERVER:SSL:yaSSL, SERVER:OPTIMIZER,
  SERVER:INNODB DML FOREIGN KEYS.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially
  sensitive information, gain escalated privileges, manipulate certain data, cause a DoS (Denial of Service),
  and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Oracle MySQL 5.5.39 and prior, 5.6.20 and prior.");

  script_tag(name:"solution", value:"Update to version 5.5.40, 5.6.21 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2014.html#AppendixMSQL");

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

if (version_is_less_equal(version: version, test_version: "5.5.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.40", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.6", test_version2: "5.6.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
