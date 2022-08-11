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
  script_oid("1.3.6.1.4.1.25623.1.0.148425");
  script_version("2022-07-12T06:23:54+0000");
  script_tag(name:"last_modification", value:"2022-07-12 06:23:54 +0000 (Tue, 12 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-12 05:33:12 +0000 (Tue, 12 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-2097", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215",
                "CVE-2022-32212");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 14.x < 14.20.0, 16.x < 16.16.0, 18.x < 18.5.0 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-32213: HTTP request smuggling due to flawed parsing of Transfer-Encoding

  - CVE-2022-32214: HTTP request smuggling due to improper delimiting of header fields

  - CVE-2022-32215: HTTP request smuggling due to incorrect parsing of multi-line Transfer-Encoding

  - CVE-2022-32212: DNS rebinding in --inspect via invalid IP addresses

  - CVE-2022-2097: OpenSSL AES OCB fails to encrypt some bytes");

  script_tag(name:"affected", value:"Node.js version 14.x prior to 14.20.0, 16.x prior to 16.16.0
  and 18.x prior to 18.5.0.");

  script_tag(name:"solution", value:"Update to version 14.20.0, 16.16.0, 18.5.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2022-security-releases/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.20.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.20.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
