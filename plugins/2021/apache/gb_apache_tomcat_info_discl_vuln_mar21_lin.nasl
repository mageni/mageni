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
  script_oid("1.3.6.1.4.1.25623.1.0.145479");
  script_version("2021-03-02T05:23:26+0000");
  script_tag(name:"last_modification", value:"2021-03-02 12:14:25 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-02 05:17:13 +0000 (Tue, 02 Mar 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-25122");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Information Disclosure Vulnerability (Mar21) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"When responding to new h2c connection requests, Apache Tomcat could
  duplicate request headers and a limited amount of request body from one request to another meaning user A
  and user B could both see the results of user A's request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.x - 8.5.61, 9.0.0.M1 - 9.0.41 and 10.0.x prior to 10.0.1.");

  script_tag(name:"solution", value:"Update to version 8.5.63, 9.0.43, 10.0.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r7b95bc248603360501f18c8eb03bb6001ec0ee3296205b34b07105b7@%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.2");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.43");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.63");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.61")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.63", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.41") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.43", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^10\.0\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
