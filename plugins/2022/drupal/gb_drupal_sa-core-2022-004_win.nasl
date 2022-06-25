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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113843");
  script_version("2022-03-18T14:03:48+0000");
  script_tag(name:"last_modification", value:"2022-03-18 14:03:48 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-18 08:49:54 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 14:34:00 +0000 (Fri, 25 Feb 2022)");

  script_cve_id("CVE-2022-25270");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Information Disclosure Vulnerability (SA-CORE-2022-004) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Quick Edit module does not properly check entity access in
  some circumstances. This could result in users with the 'access in-place editing' permission
  viewing some content they are not authorized to access.");

  script_tag(name:"affected", value:"Drupal version 8.x and 9.x.

  Sites are only affected if the QuickEdit module (which comes with the Standard profile) is
  installed.");

  script_tag(name:"solution", value:"Update to version 9.2.13, 9.3.6 or later.

  Uninstalling the QuickEdit module will also mitigate the vulnerability.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-004");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "9.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
