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
  script_oid("1.3.6.1.4.1.25623.1.0.144825");
  script_version("2020-10-26T06:41:59+0000");
  script_tag(name:"last_modification", value:"2020-10-26 11:10:40 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-26 06:34:20 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-1472");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Zerologon Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to the Zerologon vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If exploited, this elevation of privilege vulnerability allows remote
  attackers to bypass security measures via a compromised QTS device on the network. The NAS may be exposed to
  this vulnerability if users have configured the device as a domain controller in Control Panel >
  Network & File Services > Win/Mac/NFS > Microsoft Networking.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.3.3, 4.3.4, 4.3.6, 4.4.3 and 4.5.1.");

  script_tag(name:"solution", value:"Update to version 4.3.3.1432 build 20201006, 4.3.4.1463 build 20201006,
  4.3.6.1446 Build 20200929, 4.4.3.1439 build 20200925, 4.5.1.1456 build 20201015 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-07");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "4.3.3", test_version2: "4.3.3_20201005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20201006");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20201005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20201006");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.6", test_version2: "4.3.6_20200928")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20200929");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4.3", test_version2: "4.4.3_20200924")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3_20200925");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.1", test_version2: "4.5.1_20201014")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1_20201015");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
