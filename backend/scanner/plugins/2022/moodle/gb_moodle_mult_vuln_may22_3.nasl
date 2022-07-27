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
  script_oid("1.3.6.1.4.1.25623.1.0.124073");
  script_version("2022-06-02T14:05:43+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-31 03:47:16 +0000 (Tue, 31 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 12:48:00 +0000 (Thu, 26 May 2022)");

  script_cve_id("CVE-2022-30597", "CVE-2022-30598", "CVE-2022-30599", "CVE-2022-30600");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle Multiple Vulnerabilities (MSA-22-0011, MSA-22-0012, MSA-22-0013, MSA-22-0014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-22-0011 / CVE-2022-30597: Privilege escalation

  - MSA-22-0012 / CVE-2022-30598: Information disclosure

  - MSA-22-0013 / CVE-2022-30599: SQL injection

  - MSA-22-0014 / CVE-2022-30600: Information disclosure");

  script_tag(name:"affected", value:"Moodle prior to version 3.9.14, version 3.10.x through 3.10.10,
  3.11.x through 3.11.6 and 4.0");

  script_tag(name:"solution", value:"Update to version 3.9.14, 3.10.11, 3.11.7, 4.0.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=434579");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=434580");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=434581");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=434582");

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

if (version_is_less(version: version, test_version: "3.9.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.10.0", test_version2: "3.10.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.11.0", test_version2: "3.11.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
