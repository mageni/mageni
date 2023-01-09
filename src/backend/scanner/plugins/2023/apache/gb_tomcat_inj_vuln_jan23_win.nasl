# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149062");
  script_version("2023-01-04T10:13:11+0000");
  script_tag(name:"last_modification", value:"2023-01-04 10:13:11 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-04 02:28:46 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-45143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat JsonErrorReportValve Injection Vulnerability (Jan 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a JsonErrorReportValve injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The JsonErrorReportValve did not escape the type, message or
  description values. In some circumstances these are constructed from user provided data and it
  was therefore possible for users to supply values that invalidated or manipulated the JSON
  output.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.83, 9.0.40 through 9.0.68 and
  10.0.0-M1 through 10.1.1.");

  script_tag(name:"solution", value:"Update to version 8.5.84, 9.0.69, 10.1.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/yqkd183xrw3wqvnpcg3osbcryq85fkzj");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "8.5.83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.84", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.40", test_version_up: "9.0.69")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.69", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0.M1", test_version_up: "10.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
