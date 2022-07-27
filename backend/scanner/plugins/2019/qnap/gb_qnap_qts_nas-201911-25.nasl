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

CPE_PREFIX = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143218");
  script_version("2019-12-05T04:29:14+0000");
  script_tag(name:"last_modification", value:"2019-12-05 04:29:14 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-05 02:38:48 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-7192", "CVE-2019-7193", "CVE-2019-7194", "CVE-2019-7195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (NAS-201911-25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"QNAP QTS is prone to multiple vulnerabilities:

  - Improper access control vulnerability allows remote attackers to gain unauthorized access to the system (CVE-2019-7192)

  - Improper input validation vulnerability allows remote attackers to inject arbitrary code to the system (CVE-2019-7193)

  - External control of file name or path vulnerability allows remote attackers to access or modify system files
    (CVE-2019-7194, CVE-2019-7195)");

  script_tag(name:"affected", value:"QNAP QTS versions 4.3.6 and 4.4.0 - 4.4.1.");

  script_tag(name:"solution", value:"Update to version 4.3.6 build 20190919, 4.4.1 build 20190918 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201911-25");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.4.0", test_version2: "4.4.1_20190917")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1_20190918");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.6", test_version2: "4.3.6_20190918")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20190919");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
