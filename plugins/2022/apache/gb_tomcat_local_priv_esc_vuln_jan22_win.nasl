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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117945");
  script_version("2022-01-27T08:49:46+0000");
  script_tag(name:"last_modification", value:"2022-01-27 08:49:46 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-27 08:18:10 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-23181");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Local Privilege Escalation Vulnerability (Jan 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"insight", value:"The fix for bug CVE-2020-9484 introduced a time of check, time
  of use vulnerability that allowed a local attacker to perform actions with the privileges of the
  user that the Tomcat process is using. This issue is only exploitable when Tomcat is configured to
  persist sessions using the FileStore.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.55 through 8.5.73, 9.0.35 through 9.0.56,
  10.0.0-M5 through 10.0.14 and 10.1.0-M1 through 10.1.0-M8.");

  script_tag(name:"solution", value:"Update to version 8.5.75, 9.0.58, 10.0.16, 10.1.0-M10 or later.

  Note: This issue was fixed in Apache Tomcat 10.1.0-M9, 10.0.15, 9.0.57 and 8.5.74 but the release
  vote for those release candidates did not pass. Therefore, although users must download
  10.1.0-M10, 10.0.16, 9.0.58 or 8.5.75 to obtain a version that includes a fix for this issue,
  versions 10.1.0-M9, 10.0.15, 9.0.57 and 8.5.74 are not included in the list of affected versions.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.0-M10");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.16");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.58");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.75");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/0rzopt00r4dksgrtyxsmqjyhl8xrhv7p");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.5.55", test_version2: "8.5.73")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.75", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.35", test_version2: "9.0.56")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.58", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0-M5") >= 0) && (revcomp(a: version, b: "10.0.14") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.1.0-M") >= 0) && (revcomp(a: version, b: "10.1.0-M8") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0-M10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
