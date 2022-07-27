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

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117726");
  script_version("2021-10-18T06:46:24+0000");
  script_tag(name:"last_modification", value:"2021-10-18 10:42:08 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-18 06:39:16 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-42340");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Oct 2021) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"The fix for bug 63362 introduced a memory leak. The object
  introduced to collect metrics for HTTP upgrade connections was not released for WebSocket
  connections once the WebSocket connection was closed. This created a memory leak that, over time,
  could lead to a denial of service via an OutOfMemoryError.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.60 through 8.5.71, 9.0.40 through 9.0.53,
  10.0.0-M10 through 10.0.11 and 10.1.0-M1 through 10.1.0-M5.");

  script_tag(name:"solution", value:"Update to version 8.5.72, 9.0.54, 10.0.12, 10.1.0-M6 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r83a35be60f06aca2065f188ee542b9099695d57ced2e70e0885f905c%40%3Cannounce.tomcat.apache.org%3E");

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

if (version_in_range(version: version, test_version: "8.5.60", test_version2: "8.5.71")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.72", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.40", test_version2: "9.0.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0-M10") >= 0) && (revcomp(a: version, b: "10.0.11") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.1.0-M1") >= 0) && (revcomp(a: version, b: "10.1.0-M5") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0-M6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);