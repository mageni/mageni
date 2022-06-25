# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112490");
  script_version("2021-02-12T10:44:24+0000");
  script_tag(name:"last_modification", value:"2021-02-15 11:14:46 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-01-16 13:12:11 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-2434", "CVE-2019-2510", "CVE-2019-2420", "CVE-2019-2528", "CVE-2019-2486",
                "CVE-2019-2532");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server 5.7 <= 5.7.24 / 8.0 <= 8.0.13 Security Update (cpujan2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The attacks range in variety and difficulty. Most of them allow an attacker
  with network access via multiple protocols to compromise the MySQL Server.

  For further information refer to the official advisory via the referenced link.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can result in unauthorized
  access to critical data or complete access to all MySQL Server accessible data and unauthorized ability
  to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.7 through 5.7.24 and 8.0 through 8.0.13.");

  script_tag(name:"solution", value:"Updates are available. Apply the necessary patch from the referenced link.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2019.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2019");

  exit(0);
}

CPE = "cpe:/a:oracle:mysql";

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

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