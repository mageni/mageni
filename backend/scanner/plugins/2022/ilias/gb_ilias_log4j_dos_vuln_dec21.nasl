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

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117947");
  script_version("2022-01-28T10:15:13+0000");
  script_tag(name:"last_modification", value:"2022-01-28 11:09:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-28 09:13:52 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-30 16:22:00 +0000 (Thu, 30 Dec 2021)");

  script_cve_id("CVE-2021-45105");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS 6.x <= 6.14, 7.x < 7.6 ilServer Log4j DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"The ilServer Java component of ILIAS is using a version of the
  Apache Log4j library which is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaw exists in the Log4j library used by the
  ilServer component:

  Apache Log4j2 did not protect from uncontrolled recursion from self-referential lookups. When the
  logging configuration uses a non-default Pattern Layout with a Context Lookup (for example,
  $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can craft
  malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will
  terminate the process.");

  script_tag(name:"affected", value:"The ilServer Java component in ILIAS versions 6.x through 6.14
  and 7.x prior to 7.6.

  Note: The 5.x branch wasn't affected by this flaw because the release 5.4.26 has updated the Log4j
  version from 1.2.15 directly to 2.17.0.");

  script_tag(name:"solution", value:"Update to version 7.6 or later.

  Notes:

  - This release updated the Log4j version used in the ilServer component from 2.16.0 to 2.17.0

  - The 6.x branch hasn't received an update yet");

  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v7.5...v7.6");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_130118_35.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p6xc-xr62-6r2g");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");

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

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
