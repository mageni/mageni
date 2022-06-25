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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146650");
  script_version("2021-09-13T09:15:10+0000");
  script_tag(name:"last_modification", value:"2021-09-13 10:26:09 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-13 08:58:04 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");

  script_cve_id("CVE-2021-28816", "CVE-2021-34343");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Buffer Overflow Vulnerabilities (QSA-21-33)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Two stack buffer overflow vulnerabilities have been reported to
  affect QNAP devices running QTS. If exploited, these vulnerabilities allow attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"QNAP NAS QTS prior versions 4.3.3.1693 build 20210624,
  4.3.6.1750 build 20210730, 4.5.4.1715 build 20210630 and 5.0.0.1716 build 20210701.");

  script_tag(name:"solution", value:"Update to version 4.3.3.1693 build 20210624,
  4.3.6.1750 build 20210730, 4.5.4.1715 build 20210630, 5.0.0.1716 build 20210701 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-33");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.3_20210624")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20210624");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.6_20210729")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20210730");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.4", test_version2: "4.5.4_20210629")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.4_20210630");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.0_20210700")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.0_20210701");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
