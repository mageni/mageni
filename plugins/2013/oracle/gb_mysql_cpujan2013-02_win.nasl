# Copyright (C) 2021 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117203");
  script_version("2021-02-10T14:51:52+0000");
  script_tag(name:"last_modification", value:"2021-02-12 11:04:26 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-09 06:15:31 +0000 (Tue, 09 Feb 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2012-5611", "CVE-2013-0384", "CVE-2013-0389", "CVE-2013-0385", "CVE-2013-0375",
                "CVE-2012-1702", "CVE-2013-0383", "CVE-2012-0572", "CVE-2012-0574", "CVE-2012-1705",
                "CVE-2012-4414"); # From the vendor advisory: CVE-2013-0375 and CVE-2012-4414 are equivalent.

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL <= 5.1.66 / 5.5 <= 5.5.28 Security Update (cpujan2013) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL versions 5.1.66 and prior and 5.5 through 5.5.28.");

  script_tag(name:"solution", value:"Update to version 5.1.67, 5.5.29 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2013.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujan2013");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.1.66")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.67", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.28")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);