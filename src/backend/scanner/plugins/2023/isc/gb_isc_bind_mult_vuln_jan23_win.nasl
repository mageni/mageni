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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126311");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-26 09:55:12 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-3736", "CVE-2022-3924");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND Multiple DoS Vulnerabilities (CVE-2022-3736, CVE-2022-3924) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ISC BIND is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3736: Answer from stale cache may terminate unexpectedly while processing RRSIG
  queries.

  - CVE-2022-3924: named configured to answer from stale cache may terminate unexpectedly at
  recursive-clients soft quota.");

  script_tag(name:"affected", value:"ISC BIND versions 9.16.12 through 9.16.36, 9.18.0 through
  9.18.10, 9.19.0 through 9.19.8 and 19.16.12-S1 through 19.16.36-S1");

  script_tag(name:"solution", value:"Update to version 9.16.37, 9.18.11, 9.19.9, 9.16.37-S1 or
  later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2022-3736");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2022-3924");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version =~ "^9\.[0-9]+\.[0-9]+s[0-9]") {
  if (version_in_range(version: version, test_version: "9.16.12s1", test_version2: "9.16.36s1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.37-S1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.16.12", test_version2: "9.16.36")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.37", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.18.0", test_version2: "9.18.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.18.11", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.19.0", test_version2: "9.19.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.19.9", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
 }

exit(99);
