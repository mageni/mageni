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
  script_oid("1.3.6.1.4.1.25623.1.0.146267");
  script_version("2021-07-13T05:53:45+0000");
  script_tag(name:"last_modification", value:"2021-07-13 11:35:30 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 05:43:44 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-33037");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat HTTP Request Smuggling Vulnerability (Jul 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an HTTP request smuggling vulnerability.");

  script_tag(name:"insight", value:"Apache Tomcat does not correctly parse the HTTP transfer-encoding
  request header in some circumstances leading to the possibility to request smuggling when used
  with a reverse proxy. Specifically: Tomcat incorrectly ignores the transfer-encoding header if
  the client declared it would only accept an HTTP/1.0 response. Tomcat honours the identify
  encoding and Tomcat does not ensure that, if present, the chunked encoding is the final encoding.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.x through 8.5.66, 9.0.0.M1 through 9.0.46
  and 10.0.0-M1 through 10.0.6.");

  script_tag(name:"solution", value:"Update to version 8.5.68, 9.0.48, 10.0.7 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r612a79269b0d5e5780c62dfd34286a8037232fec0bc6f1a7e60c9381%40%3Cannounce.tomcat.apache.org%3E");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.7");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.48");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.68");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.66")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.68", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0.M1") >= 0) && (revcomp(a: version, b: "9.0.46") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.48", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "10.0.0.M1") >= 0) && (revcomp(a: version, b: "10.0.6") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
