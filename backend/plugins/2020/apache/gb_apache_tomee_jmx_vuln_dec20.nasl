# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tomee";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145079");
  script_version("2020-12-21T10:10:27+0000");
  script_tag(name:"last_modification", value:"2020-12-21 15:00:31 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-21 09:53:06 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-13931");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache TomEE JMX Vulnerability (CVE-2020-13931)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomee_server_detect.nasl");
  script_mandatory_keys("apache/tomee/detected");

  script_tag(name:"summary", value:"Apache TomEE is prone to a misconfiguration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If Apache TomEE is configured to use the embedded ActiveMQ broker, and the
  broker config is misconfigured, a JMX port is opened on TCP port 1099, which does not include authentication.
  CVE-2020-11969 previously addressed the creation of the JMX management interface, however the incomplete fix did
  not cover this edge case.");

  script_tag(name:"affected", value:"Apache TomEE versions 1.0.0 - 1.7.5, 7.0.0-M1 - 7.0.8, 7.1.0 - 7.1.3 and
  8.0.0-M1 - 8.0.3.");

  script_tag(name:"solution", value:"Update to version 7.0.9, 7.1.4, 8.0.4 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/ref088c4732e1a8dd0bbbb96e13ffafcfe65f984238ffa55f438d78fe%40%3Cdev.tomee.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.0.0", test_version2: "1.7.5") ||
    version_in_range(version: version, test_version: "7.0.0.M1", test_version2: "7.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.1.0", test_version2: "7.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0.M1", test_version2: "8.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
