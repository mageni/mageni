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

CPE = "cpe:/a:qnap:music_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145965");
  script_version("2021-05-18T06:12:48+0000");
  script_tag(name:"last_modification", value:"2021-05-18 10:15:22 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-18 06:06:11 +0000 (Tue, 18 May 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2020-36197");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Music Station Improper Access Control Vulnerability (QSA-21-08)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_musicstation_detect.nasl");
  script_mandatory_keys("qnap_musicstation/detected");

  script_tag(name:"summary", value:"QNAP Music Station is prone to an improper access control
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this vulnerability allows attackers to compromise
  the security of the software by gaining privileges, reading sensitive information,
  executing commands, evading detection, etc.");

  script_tag(name:"affected", value:"QNAP Music Station versions prior to 5.1.14 (QTS 4.3.3), 5.2.10
  (QTS 4.3.6) and 5.3.16 (QTS 4.5.2).");

  script_tag(name:"solution", value:"Update to version 5.1.14, 5.2.10, 5.3.16 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-08");

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

if (version_is_less(version: version, test_version: "5.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
