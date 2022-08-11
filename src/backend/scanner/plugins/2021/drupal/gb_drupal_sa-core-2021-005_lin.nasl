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
  script_oid("1.3.6.1.4.1.25623.1.0.146509");
  script_version("2021-08-13T02:29:36+0000");
  script_tag(name:"last_modification", value:"2021-08-13 10:29:13 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-13 02:18:41 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2021-32808", "CVE-2021-32809");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.9.x < 8.9.18, 9.x < 9.1.12, 9.2.x < 9.2.4 Multiple CKEditor Library Vulnerabilities (SA-CORE-2021-005) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a vulnerability in the third-party library
  CKEditor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal project uses the CKEditor, library for WYSIWYG editing.
  CKEditor has released a security update that impacts Drupal.

  Vulnerabilities are possible if Drupal is configured to allow use of the CKEditor library for
  WYSIWYG editing. An attacker that can create or edit content (even without access to CKEditor
  themselves) may be able to exploit one or more Cross-Site Scripting (XSS) vulnerabilities to
  target users with access to the WYSIWYG CKEditor, including site admins with privileged access.");

  script_tag(name:"affected", value:"Drupal version 8.9.x through 8.9.17, 9.x through 9.1.11 and
  9.2.x through 9.2.3.");

  script_tag(name:"solution", value:"Update to version 8.9.18, 9.1.12, 9.2.4 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-005");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.9.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.2", test_version2: "9.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
