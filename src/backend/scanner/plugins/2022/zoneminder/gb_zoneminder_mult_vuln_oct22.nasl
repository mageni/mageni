# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148945");
  script_version("2022-11-24T10:18:54+0000");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-23 08:18:46 +0000 (Wed, 23 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2022-39285", "CVE-2022-39289", "CVE-2022-39290", "CVE-2022-39291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder < 1.36.27, 1.37.x < 1.37.24 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-39285: Stored cross-site scripting (XSS) in file parameter

  - CVE-2022-39289: API exposes database log contents to user without privileges, allows insertion,
  modification, deletion of logs without system privileges

  - CVE-2022-39290: CSRF key bypass using HTTP methods

  - CVE-2022-39291: Denial of service (DoS) through logs");

  script_tag(name:"affected", value:"ZoneMinder version 1.36.26 and prior and 1.37.x through
  1.37.23.");

  script_tag(name:"solution", value:"Update to version 1.36.27, 1.37.24 or later.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-h6xp-cvwv-q433");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-mpcx-3gvh-9488");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-xgv6-qv6c-399q");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-cfcx-v52x-jh74");

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

if (version_is_less(version: version, test_version: "1.36.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.37.0", test_version_up: "1.37.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
