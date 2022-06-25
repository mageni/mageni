# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:isc:bind';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140837");
  script_version("2019-06-21T02:23:48+0000");
  script_tag(name:"last_modification", value:"2019-06-21 02:23:48 +0000 (Fri, 21 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-21 02:06:15 +0000 (Fri, 21 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-6471");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability - CVE-2019-6471 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability when discarding
  malformed packets.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A race condition which may occur when discarding malformed packets can result
  in BIND exiting due to a REQUIRE assertion failure in dispatch.c.");

  script_tag(name:"impact", value:"An attacker who can cause a resolver to perform queries which will be answered
  by a server which responds with deliberately malformed answers can cause named to exit, denying service to clients.");

  script_tag(name:"affected", value:"ISC BIND versions 9.11.0 to 9.11.7, 9.12.0 to 9.12.4-P1, 9.14.0 to 9.14.2, all
  releases of the BIND 9.13 development branch, 9.15.0 and  BIND Supported Preview Edition versions 9.11.3-S1 to 9.11.7-S1.");

  script_tag(name:"solution", value:"Update to version 9.11.8, 9.12.4-P2, 9.14.3, 9.15.1, 9.11.8-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2019-6471");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version !~ "^9\.")
  exit(0);

if (version =~ "9\.11\.[0-9]\.S[0-9]") {
  if (version_in_range(version: version, test_version: "9.11.3.S1", test_version2: "9.11.7.S1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.8-S1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}
else {
  if (version_in_range(version: version, test_version: "9.11.0", test_version2: "9.11.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.8");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.4.P1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.12.4-P2");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version =~ "^9\.13\.") {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.14.0", test_version2: "9.14.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "9.15.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.15.1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
