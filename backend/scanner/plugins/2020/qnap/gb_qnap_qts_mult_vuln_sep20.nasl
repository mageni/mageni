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

CPE_PREFIX = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144533");
  script_version("2020-09-08T02:57:09+0000");
  script_tag(name:"last_modification", value:"2020-09-08 09:56:35 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-08 02:11:20 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-7418", "CVE-2019-19269", "CVE-2019-19270", "CVE-2019-18217", "CVE-2019-19272",
                "CVE-2019-19271", "CVE-2020-9273", "CVE-2020-9272", "CVE-2020-10745");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple ProFTPD Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities in ProFTPD and other components.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Local security bypass in ProFTPD (CVE-2017-7418)

  - Multiple NULL pointer dereferences in ProFTPD (CVE-2019-19269, CVE-2019-19272)

  - Multiple improper certificate validations in ProFTPD (CVE-2019-19270, CVE-2019-19271)

  - Denial of service vulnerability in ProFTPD (CVE-2019-18217)

  - Use-after-free in ProFTPD that could be exploited for arbitrary code execution (CVE-2020-9273)

  - Out-of-bounds read in ProFTPD (CVE-2020-9272)

  - UDP flood denial-of-service in Samba Active Directory Domain Controller (AD DC)

  - Resource exhaustion in Samba Active Directory domain controller (CVE-2020-10745)");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6, 4.3.3, 4.3.4, 4.3.6 and 4.4.3.");

  script_tag(name:"solution", value:"Update to version 4.2.6 build 20200821, 4.3.3.1386 build 20200821,
  4.3.4.1417 build 20200821, 4.3.6.1411 Build 20200825, 4.4.3.1400 build 20200817 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/4.4.3.1400/20200817");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.2.6", test_version2: "4.2.6_20200820")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20200821");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.3", test_version2: "4.3.3_20200820")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20200821");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20200820")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20200821");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.6", test_version2: "4.3.6_20200824")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20200825");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.3", test_version2: "4.4.3_20200816")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1_20200817");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
