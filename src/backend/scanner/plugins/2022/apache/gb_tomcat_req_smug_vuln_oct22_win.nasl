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
  script_oid("1.3.6.1.4.1.25623.1.0.148840");
  script_version("2022-11-03T10:20:15+0000");
  script_tag(name:"last_modification", value:"2022-11-03 10:20:15 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-02 09:19:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-42252");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Request Smuggling Vulnerability (Oct 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If Tomcat is configured to ignore invalid HTTP headers via
  setting rejectIllegalHeader to false (the default for 8.5.x only), Tomcat does not reject a
  request containing an invalid Content-Length header making a request smuggling attack possible if
  Tomcat is located behind a reverse proxy that also fails to reject the request with the invalid
  header.");

  script_tag(name:"affected", value:"Apache Tomcat version 8.5.0 through 8.5.82, 9.0.0-M1 through
  9.0.67, 10.0.0-M1 through 10.0.26 and 10.1.0.");

  script_tag(name:"solution", value:"Update to version 8.5.83, 9.0.68, 10.0.27, 10.1.1 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/zzcxzvqfdqn515zfs3dxb7n8gty589sq");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.83", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.68")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0.M1", test_version_up: "10.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0.M1", test_version_up: "10.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
