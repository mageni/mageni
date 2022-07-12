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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145959");
  script_version("2021-05-17T07:13:15+0000");
  script_tag(name:"last_modification", value:"2021-05-17 10:34:03 +0000 (Mon, 17 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 07:04:11 +0000 (Mon, 17 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-26216", "CVE-2020-26227", "CVE-2020-26228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2020-009, TYPO3-CORE-SA-2020-010, TYPO3-CORE-SA-2020-011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-26216: Cross-site scripting (XSS) through Fluid view helper arguments

  - CVE-2020-26227: Cross-site scripting (XSS) in Fluid view helpers

  - CVE-2020-26228: Cleartext storage of session identifier");

  script_tag(name:"affected", value:"TYPO3 version 6.2.0 through 6.2.53, 7.6.0 through 7.6.47, 8.7.0
  through 8.7.37, 9.0.0 through 9.5.22 and 10.0.0 through 10.4.9.");

  script_tag(name:"solution", value:"Update to version 6.2.54, 7.6.48, 8.7.38, 9.5.23, 10.4.10 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-009");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-010");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-011");

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

if (version_in_range(version: version, test_version: "6.2.0", test_version2: "6.2.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.6.0", test_version2: "7.6.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.48", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.7.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
