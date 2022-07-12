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
  script_oid("1.3.6.1.4.1.25623.1.0.104203");
  script_version("2022-05-13T12:34:56+0000");
  script_tag(name:"last_modification", value:"2022-05-16 10:05:13 +0000 (Mon, 16 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-13 12:23:08 +0000 (Fri, 13 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-25762");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Request Mix-up Vulnerability (May 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a request mix-up vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If a web application sends a WebSocket message concurrently with
  the WebSocket connection closing, it is possible that the application will continue to use the
  socket after it has been closed. The error handling triggered in this case could cause the a
  pooled object to be placed in the pool twice. This could result in subsequent connections using
  the same object concurrently which could result in data being returned to the wrong use and/or
  other errors.");

  script_tag(name:"affected", value:"Apache Tomcat 8.5.0 through 8.5.75 and 9.0.0.M1 through
  9.0.20.");

  script_tag(name:"solution", value:"Update to version 8.5.76, 9.0.21 or later.");

  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.21");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.76");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/tkmozotlgcrpvhx5vt6kw0pxtfx11k67");

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

if (version_in_range(version: version, test_version: "8.5.0", test_version2: "8.5.75")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.76", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "9.0.0-M1") >= 0) && (revcomp(a: version, b: "9.0.20") <= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
