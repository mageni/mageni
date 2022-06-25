###############################################################################
# OpenVAS Vulnerability Test
#
# TYPO3 Multiple Vulnerabilities (Jan19)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141924");
  script_version("2019-05-13T07:00:34+0000");
  script_tag(name:"last_modification", value:"2019-05-13 07:00:34 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-25 15:03:35 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-14041");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple Vulnerabilities (Jan19)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"TYPO3 is prone to multiple vulnerabilities:

  - Information Disclosure of Installed Extensions

  - Security Misconfiguration for Backend User Accounts

  - Cross-Site Scripting in Fluid ViewHelpers

  - Cross-Site Scripting in Bootstrap CSS toolkit (CVE-2018-14041)

  - Cross-Site Scripting in Form Framework

  - Arbitrary Code Execution via File List Module");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TYPO3 versions 8.0.0-8.7.22 and 9.0.0-9.5.3.");

  script_tag(name:"solution", value:"Update to version 8.7.23, 9.5.4 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-001/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-002/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-005/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-006/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-007/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-008/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.23", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.4", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
