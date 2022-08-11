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

CPE = "cpe:/a:openmrs:openmrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147711");
  script_version("2022-02-28T04:40:11+0000");
  script_tag(name:"last_modification", value:"2022-02-28 11:04:36 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-28 04:26:43 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2022-23612");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenMRS 1.6 - 2.5.x Directory Traversal Vulnerability (GHSA-8rgr-ww69-jv65)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openmrs_detect.nasl");
  script_mandatory_keys("openmrs/detected");

  script_tag(name:"summary", value:"OpenMRS is prone to a directory traversal vulnerability in the
  startup filter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary file exfiltration due to failure to sanitize request
  when satisfying GET requests for /images & /initfilter/scripts.");

  script_tag(name:"impact", value:"An attacker may access any file on a system running OpenMRS that
  is accessible to the user id OpenMRS is running under.");

  script_tag(name:"affected", value:"OpenMRS version 1.6 through 2.5.x.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://talk.openmrs.org/t/security-advisory-2022-02-22-re-path-traversal-vulnerability/35930");
  script_xref(name:"URL", value:"https://github.com/openmrs/openmrs-core/security/advisories/GHSA-8rgr-ww69-jv65");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.6", test_version_up: "2.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.2", test_version_up: "2.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.3", test_version_up: "2.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.4", test_version_up: "2.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.5", test_version_up: "2.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
