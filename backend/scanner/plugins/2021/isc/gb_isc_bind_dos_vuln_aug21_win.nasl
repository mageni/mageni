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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117684");
  script_version("2021-09-17T10:40:50+0000");
  script_tag(name:"last_modification", value:"2021-09-20 10:59:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-17 10:31:32 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability (Aug 2021) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("isc/bind/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"named failed to check the opcode of responses when performing
  zone refreshes, stub zone updates, and UPDATE forwarding. This could lead to an assertion failure
  under certain conditions and has been addressed by rejecting responses whose opcode does not match
  the expected value.");

  script_tag(name:"affected", value:"BIND version prior to 9.11.35, 9.16.x prior 9.16.20 and 9.17.x
  prior to 9.17.17.");

  script_tag(name:"solution", value:"Update to version 9.11.35, 9.16.20, 9.17.17 or later.");

  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.17.17/doc/arm/html/notes.html#notes-for-bind-9-17-17");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.16.20/doc/arm/html/notes.html#notes-for-bind-9-16-20");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.11.35/doc/arm/notes.html#relnotes-9.11.35");

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

if (version =~ "^9\.") {
  if (version_is_less(version: version, test_version: "9.11.35")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.35", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "9.16.0") &&
      version_is_less(version: version, test_version: "9.16.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.16.20", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_is_greater_equal(version: version, test_version: "9.17.0") &&
      version_is_less(version: version, test_version: "9.17.17")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.17.17", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);