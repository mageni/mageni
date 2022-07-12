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
  script_oid("1.3.6.1.4.1.25623.1.0.144442");
  script_version("2020-08-21T03:43:58+0000");
  script_tag(name:"last_modification", value:"2020-08-21 10:00:44 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-21 03:43:19 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-8622", "CVE-2020-8623");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Multiple DoS Vulnerabilities - CVE-2020-8622, CVE-2020-8623 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ISC BIND is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A truncated TSIG response can lead to an assertion failure (CVE-2020-8622)

  - A flaw in native PKCS#11 code can lead to a remotely triggerable assertion failure in pk11.c (CVE-2020-8623)");

  script_tag(name:"affected", value:"BIND 9.10.0 - 9.11.21, 9.12.0 - 9.16.5, 9.17.0 - 9.17.3 and 9.10.5-S1 - 9.11.21-S1.");

  script_tag(name:"solution", value:"Update to version 9.11.22, 9.16.6, 9.17.4, 9.11.22-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2020-8622");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2020-8623");

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
  if (version_in_range(version: version, test_version: "9.10.5s1", test_version2: "9.11.21s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.22-S1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.10.0", test_version2: "9.11.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.22");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.16.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.6");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.17.0", test_version2: "9.17.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.17.4");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
