# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.143313");
  script_version("2020-01-07T03:27:48+0000");
  script_tag(name:"last_modification", value:"2020-01-07 03:27:48 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-07 03:23:16 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-17563");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Session Fixation Vulnerability - Dec19 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a session fixation vulnerability.");

  script_tag(name:"insight", value:"When using FORM authentication there was a narrow window where an attacker
  could perform a session fixation attack. The window was considered too narrow for an exploit to be practical
  but, erring on the side of caution, this issue has been treated as a security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 7.0.0 to 7.0.98, 8.5.0 to 8.5.49 and 9.0.0.M1 to 9.0.29.");

  script_tag(name:"solution", value:"Update to version 7.0.99, 8.5.50, 9.0.30 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/8b4c1db8300117b28a0f3f743c0b9e3f964687a690cdf9662a884bbd%40%3Cannounce.tomcat.apache.org%3E");

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

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.98")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.99", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.49")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.50", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.29") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
