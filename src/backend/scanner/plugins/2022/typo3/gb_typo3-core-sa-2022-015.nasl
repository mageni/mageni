# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.126255");
  script_version("2022-12-15T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 11:26:09 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-23503");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Arbitrary Code Execution Vulnerability (TYPO3-CORE-SA-2022-015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The lack of separating user-submitted data from the internal
  configuration in the Form Designer backend module.");

  script_tag(name:"affected", value:"TYPO3 version 8.0.0 through 8.7.48 ELTS, 9.0.0 through 9.5.37
  ELTS, 10.0.0 through 10.4.32, 11.0.0 through 11.5.19 and 12.0.0 through 12.1.0.");

  script_tag(name:"solution", value:"Update to version 8.7.49 ELTS, 9.5.38 ELTS, 10.4.33, 11.5.20,
  12.1.1 or later.

  Note: Since version 12.1.1 contains a known regression, vendor suggests to use 12.1.2 instead.");

  script_xref(name:"URL", value:"https://typo3.org/article/typo3-1211-11520-and-10433-security-releases-published");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2022-015");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.7.49")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.49", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.5.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.4.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.5.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.5.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
