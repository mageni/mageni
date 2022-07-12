# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142396");
  script_version("2019-05-10T09:25:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 09:25:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-10 09:20:37 +0000 (Fri, 10 May 2019)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-11832");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2019-011, TYPO3-CORE-SA-2019-012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TYPO3 is prone to multiple vulnerabilities:

  - Security Misconfiguration in User Session Handling

  - Possible Arbitrary Code Execution in Image Processing (CVE-2019-11832)");

  script_tag(name:"affected", value:"TYPO3 versions 8.0.0-8.7.24 and 9.0.0-9.5.5.");

  script_tag(name:"solution", value:"Update to version 8.7.25, 9.5.6 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-011/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-012/");

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

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.25", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
