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
  script_oid("1.3.6.1.4.1.25623.1.0.126082");
  script_version("2022-07-28T10:10:25+0000");
  script_tag(name:"last_modification", value:"2022-07-28 10:10:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-26 11:31:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-35649", "CVE-2022-35650", "CVE-2022-35651", "CVE-2022-35652", "CVE-2022-35653");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle <= 3.9.14, 3.10 <= 3.11.7, 4.0 <= 4.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-22-0015 / CVE-2022-35649: An omitted execution parameter resulted in a remote code execution
  risk for sites running GhostScript.

  - MSA-22-0016 / CVE-2022-35650: Insufficient path checks in a lesson question import resulted in
  an arbitrary file read risk.

  - MSA-22-0017 / CVE-2022-35651: Insufficient sanitizing of SCORM track details presented stored
  XSS and blind SSRF risks.

  - MSA-22-0018 / CVE-2022-35652: The mobile auto-login URL required additional sanitizing to
  prevent an open redirect risk.

  - MSA-22-0019 / CVE-2022-35653: CA minor reflected XSS risk was identified in the LTI module. This
  did not impact authenticated users.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.15, 3.10 through 3.11.7 and 4.0
  through 4.0.1.");

  script_tag(name:"solution", value:"Update to version 3.9.15, 3.11.8, 4.0.2 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=436456");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=436457");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=436458");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=436459");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=436460");

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

if (version_is_less(version: version, test_version: "3.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.11.0", test_version2: "3.11.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
