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

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149366");
  script_version("2023-02-27T10:17:28+0000");
  script_tag(name:"last_modification", value:"2023-02-27 10:17:28 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-27 03:50:51 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-23919");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 16.x < 16.19.1, 18.x < 18.14.1, 19.x < 19.2.0 DoS Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In some cases Node.js did does not clear the OpenSSL error
  stack after operations that may set it. This may lead to false positive errors during subsequent
  cryptographic operations that happen to be on the same thread. This in turn could be used to
  cause a denial of service.");

  script_tag(name:"affected", value:"Node.js version 16.x through 16.19.0, 18.x through 18.14.0 and
  19.x prior to 19.2.0.");

  script_tag(name:"solution", value:"Update to version 16.19.1, 18.14.1, 19.2.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/february-2023-security-releases/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.14.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "19.0", test_version_up: "19.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
