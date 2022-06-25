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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143937");
  script_version("2020-05-20T02:02:50+0000");
  script_tag(name:"last_modification", value:"2020-05-20 09:55:38 +0000 (Wed, 20 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 01:36:26 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-8616", "CVE-2020-8617");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Multiple DoS Vulnerabilities - CVE-2020-8616, CVE-2020-8617 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ISC BIND is prone to multiple denial of service vulnerabilities:

  - BIND does not sufficiently limit the number of fetches performed when processing referrals (CVE-2020-8616)

  - A logic error in code which checks TSIG validity can be used to trigger an assertion failure in tsig.c
    (CVE-2020-8617)");

  script_tag(name:"affected", value:"BIND 9.0.0 - 9.11.18, 9.12.0 - 9.12.4-P2, 9.14.0 - 9.14.11,
  9.16.0 - 9.16.2, 9.17.0 -> 9.17.1 and 9.9.3-S1 - 9.11.18-S1. Also affects all releases in the obsolete
  9.13 and 9.15 development branches.");

  script_tag(name:"solution", value:"Update to version 9.11.19, 9.14.12, 9.16.3, 9.11.19-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2020-8616");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2020-8617");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version =~ "^9\.(9|10|11)\.[0-9]+s[0-9]") {
  if (version_in_range(version: version, test_version: "9.9.3s1", test_version2: "9.11.18s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.19-S1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.11.18")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.19");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.4p2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.12");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version =~ "^9\.13\.") {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.12");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.14.0", test_version2: "9.14.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.12");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version =~ "^9\.15\.") {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.16.0", test_version2: "9.16.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.3");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.17.0", test_version2: "9.17.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
