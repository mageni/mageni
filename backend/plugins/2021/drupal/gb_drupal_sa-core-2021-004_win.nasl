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
  script_oid("1.3.6.1.4.1.25623.1.0.146347");
  script_version("2021-07-22T05:27:37+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:15:29 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-22 05:26:56 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-32610");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 7.x < 7.82, 8.0.x < 8.9.17, 9.x < 9.1.11, 9.2.x < 9.2.2 Archive_Tar library Vulnerability (SA-CORE-2021-004) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to a vulnerability in the third-party library
  Archive_Tar.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal project uses the pear Archive_Tar library, which has
  released a security update that impacts Drupal.

  The vulnerability is mitigated by the fact that Drupal core's use of the Archive_Tar library is
  not vulnerable, as it does not permit symlinks.

  Exploitation may be possible if contrib or custom code uses the library to extract tar archives
  (for example .tar, .tar.gz, .bz2, or .tlz) which come from a potentially untrusted source.");

  script_tag(name:"affected", value:"Drupal version 7.x through 7.81, 8.0.x through 8.9.16, 9.x
  through 9.1.10 and 9.2.x through 9.2.1.");

  script_tag(name:"solution", value:"Update to version 7.82, 8.9.17, 9.1.11, 9.2.2 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-004");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.81")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.82", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.2", test_version2: "9.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
