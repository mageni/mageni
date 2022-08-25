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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124139");
  script_version("2022-08-23T17:26:48+0000");
  script_tag(name:"last_modification", value:"2022-08-23 17:26:48 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-16 11:31:42 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-14321", "CVE-2020-14322");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.5 <= 3.5.12, 3.7 <= 3.7.6, 3.8 <= 3.8.3, 3.9 < 3.9.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-20-0009 / CVE-2020-14321: Course enrolments allow privilege escalation from teacher role
  into manager role.

  - MSA-20-0010 / CVE-2020-14322: yui_combo should mitigate denial of service risk.");

  script_tag(name:"affected", value:"Moodle versions 3.5 through 3.5.12, 3.7 through 3.7.6, 3.8
  through 3.8.3 and 3.9.x prior to 3.9.1.");

  script_tag(name:"solution", value:"Update to version 3.5.13, 3.7.7, 3.8.4, 3.9.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=407393");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=407394");

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

if (version_in_range(version: version, test_version: "3.5", test_version2: "3.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7", test_version2: "3.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
