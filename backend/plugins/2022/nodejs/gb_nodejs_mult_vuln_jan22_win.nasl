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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147712");
  script_version("2022-02-28T05:02:01+0000");
  script_tag(name:"last_modification", value:"2022-02-28 11:04:36 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-28 04:47:35 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-44531", "CVE-2021-44532", "CVE-2021-44533", "CVE-2022-21824");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x < 12.22.9, 14.x < 14.18.3, 16.x < 16.13.2, 17.x < 17.3.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44531: Improper handling of URI subject alternative names

  - CVE-2021-44532: Certificate verification bypass via string injection

  - CVE-2021-44533: Incorrect handling of certificate subject and issuer fields

  - CVE-2022-21824: Prototype pollution via console.table properties");

  script_tag(name:"affected", value:"Node.js version 12.x through 12.22.8, 14.x through 14.18.2,
  16.x through 16.13.1 and 17.x through 17.3.0.");

  script_tag(name:"solution", value:"Update to version 12.22.9, 14.18.3, 16.13.2, 17.3.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/jan-2022-security-releases/");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "12.0", test_version_up: "12.22.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.22.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.18.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.18.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.13.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.13.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "17.0", test_version_up: "17.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
