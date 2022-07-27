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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148413");
  script_version("2022-07-08T03:07:34+0000");
  script_tag(name:"last_modification", value:"2022-07-08 03:07:34 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-08 02:55:25 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-2047", "CVE-2022-2048");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Multiple Vulnerabilities (Jul 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2047: Invalid URI parsing may produce invalid HttpURI.authority

  - CVE-2022-2048: Invalid HTTP/2 requests can lead to denial of service");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.46 and prior, version 10.0.x through
  10.0.9 and 11.0.x through 11.0.9.");

  script_tag(name:"solution", value:"Update to version 9.4.47, 10.0.10, 11.0.10 or later.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-cj7v-27pg-wf7q");
  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-wgmr-mf83-7x4j");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "9.4.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
