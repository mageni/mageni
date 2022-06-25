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

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143916");
  script_version("2020-05-15T12:53:37+0000");
  script_tag(name:"last_modification", value:"2020-05-18 10:22:57 +0000 (Mon, 18 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-15 04:21:47 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-11063");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 10.4.x < 10.4.2 Information Disclosure Vulnerability (TYPO3-CORE-SA-2020-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");

  script_tag(name:"summary", value:"TYPO3 is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Time-based attacks can be used with the password reset functionality for
  backend users. This allows an attacker to mount user enumeration based on email addresses assigned to backend
  user accounts.");

  script_tag(name:"affected", value:"TYPO3 versions 10.4.0 - 10.4.1.");

  script_tag(name:"solution", value:"Update to version 10.4.2 or later.");

  script_xref(name:"URL", value:"https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-347x-877p-hcwx");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-001");

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

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
