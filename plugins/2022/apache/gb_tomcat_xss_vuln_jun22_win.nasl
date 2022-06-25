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
  script_oid("1.3.6.1.4.1.25623.1.0.148322");
  script_version("2022-06-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2022-06-24 05:05:31 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 05:04:26 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-34305");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat XSS Vulnerability (Jun 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Form authentication example in the examples web application
  displayed user provided data without filtering, exposing a XSS vulnerability.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.50 through 8.5.81, 9.0.30 through
  9.0.64, 10.0.0-M1 through 10.0.22 and 10.1.0-M1 through 10.1.0-M16.");

  script_tag(name:"solution", value:"Update to version 8.5.82, 9.0.65, 10.0.23, 10.1.0-M17 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/k04zk0nq6w57m72w5gb0r6z9ryhmvr4k");

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

if (version_in_range(version: version, test_version: "8.5.50", test_version2: "8.5.81")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.82", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.30", test_version2: "9.0.64")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.65", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0-M1") >= 0) && (revcomp(a: version, b: "10.0.22") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.1.0-M1") >= 0) && (revcomp(a: version, b: "10.1.0-M16") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0-M17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
