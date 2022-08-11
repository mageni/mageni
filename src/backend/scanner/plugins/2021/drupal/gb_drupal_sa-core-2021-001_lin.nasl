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

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145251");
  script_version("2021-01-25T06:02:13+0000");
  script_tag(name:"last_modification", value:"2021-01-25 11:10:13 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 05:54:17 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-36193");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 7.x, 8.x, 9.x  Archive_Tar library Vulnerability (SA-CORE-2021-001) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a vulnerability in the Archive_Tar library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal project uses the pear Archive_Tar library, which has released a
  security update that impacts Drupal.

  Exploits may be possible if Drupal is configured to allow .tar, .tar.gz, .bz2, or .tlz file uploads and
  processes them.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.9.x and prior, 9.0.x and 9.1.x.");

  script_tag(name:"solution", value:"Update to version 7.78, 8.9.13, 9.0.11, 9.1.3 or later. Disable uploads
  of .tar, .tar.gz, .bz2, or .tlz files to mitigate the vulnerability.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-001");

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

if (version_is_less(version: version, test_version: "7.78")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.78", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.9.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1", test_version2: "9.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
