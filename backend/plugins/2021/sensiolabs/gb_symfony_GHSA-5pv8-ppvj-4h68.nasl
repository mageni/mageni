# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:sensiolabs:symfony";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.145966");
  script_version("2021-05-19T02:27:25+0000");
  script_tag(name:"last_modification", value:"2021-05-19 10:30:29 +0000 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-19 02:21:14 +0000 (Wed, 19 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-21424");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony Information Disclosure Vulnerability (GHSA-5pv8-ppvj-4h68)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ability to enumerate users is possible without relevant
  permissions due to different exception messages depending on whether the user existed or not. It
  is also possible to enumerate users by using a timing attack, by comparing time elapsed when
  authenticating an existing user and authenticating a non-existing user.");

  script_tag(name:"affected", value:"Symfony version 2.8.0 through 3.4.47, 4.0.0 through 4.4.22 and
  5.0.0 through 5.2.7.");

  script_tag(name:"solution", value:"Update to version 3.4.48, 4.4.23, 5.2.8 or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-5pv8-ppvj-4h68");

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

if (version_in_range(version: version, test_version: "2.8.0", test_version2: "3.4.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.48", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
