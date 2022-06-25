# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144294");
  script_version("2021-02-10T15:21:20+0000");
  script_tag(name:"last_modification", value:"2021-02-11 11:09:43 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-07-21 08:53:58 +0000 (Tue, 21 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-1967", "CVE-2020-14663", "CVE-2020-14678", "CVE-2020-14697", "CVE-2020-14591",
                "CVE-2020-14539", "CVE-2020-14680", "CVE-2020-14619", "CVE-2020-14576", "CVE-2020-14643",
                "CVE-2020-14651", "CVE-2020-14568", "CVE-2020-14623", "CVE-2020-14540", "CVE-2020-14575",
                "CVE-2020-14620", "CVE-2020-14624", "CVE-2020-14656", "CVE-2020-14547", "CVE-2020-14597",
                "CVE-2020-14614", "CVE-2020-14654", "CVE-2020-14632", "CVE-2020-14631", "CVE-2020-14586",
                "CVE-2020-14702", "CVE-2020-14641", "CVE-2020-14559", "CVE-2020-14553", "CVE-2020-14633",
                "CVE-2020-14634", "CVE-2020-14725");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL 8.0 <= 8.0.20 Security Update (cpujul2020) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Oracle MySQL versions 8.0 through 8.0.20.");

  script_tag(name:"solution", value:"Update to version 8.0.21 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html#AppendixMSQL");
  script_xref(name:"Advisory-ID", value:"cpujul2020");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);