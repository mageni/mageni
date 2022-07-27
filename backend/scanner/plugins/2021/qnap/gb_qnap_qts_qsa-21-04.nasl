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
  script_oid("1.3.6.1.4.1.25623.1.0.145778");
  script_version("2021-04-19T04:42:58+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-19 04:37:10 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2018-19942");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS XSS Vulnerability (QSA-21-04)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to a cross-site scripting (XSS) vulnerability in
  File Station.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability has been reported to affect earlier versions of File
  Station. If exploited, this vulnerability allows remote attackers to inject malicious code.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.qnap.com/zh-tw/security-advisory/qsa-21-04");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.6_20210327")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6_20210327");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3", test_version2: "4.3.3_20201005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.3_20201006");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.4", test_version2: "4.3.4_20201005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.4_20201006");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.5", test_version2: "4.3.6_20200928")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.6_20200929");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5", test_version2: "4.5.1_20201014")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.1_20201015");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.5.2", test_version2: "4.5.2_20210201")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.2_20210202");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
