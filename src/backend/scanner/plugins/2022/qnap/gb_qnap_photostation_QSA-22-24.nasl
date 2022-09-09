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

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148706");
  script_version("2022-09-09T04:51:15+0000");
  script_tag(name:"last_modification", value:"2022-09-09 04:51:15 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-09 04:30:11 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");

  script_cve_id("CVE-2022-27593");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station Vulnerability (QSA-22-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to an externally controlled
  reference to a resource vulnerability which is e.g. used by the DeadBolt ransomware campaign.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, this could allow an attacker to modify system
  files.");

  script_tag(name:"affected", value:"QNAP Photo Station prior to version 5.2.14, 5.4.x through
  5.4.14, 5.5.x through 5.7.17, 6.x through 6.0.21 and 6.1.x through 6.1.1.");

  script_tag(name:"solution", value:"Update to version 5.2.14, 5.4.15, 5.7.18, 6.0.22, 6.1.2 or
  later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-22-24");
  script_xref(name:"URL", value:"https://attackerkb.com/topics/7We3SjEYVo/cve-2022-27593");

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

if (version_is_less(version: version, test_version: "5.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4", test_version_up: "5.4.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5", test_version_up: "5.7.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
