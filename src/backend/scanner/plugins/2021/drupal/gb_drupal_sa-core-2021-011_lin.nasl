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
  script_oid("1.3.6.1.4.1.25623.1.0.147173");
  script_version("2021-11-22T03:03:36+0000");
  script_tag(name:"last_modification", value:"2021-11-22 03:03:36 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 03:23:14 +0000 (Thu, 18 Nov 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-19 18:34:00 +0000 (Fri, 19 Nov 2021)");

  script_cve_id("CVE-2021-41164", "CVE-2021-41165");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal < 8.9.20, 9.x < 9.1.14, 9.2.x < 9.2.9 Multiple XSS Vulnerabilities (SA-CORE-2021-011) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to multiple cross-site scripting (XSS)
  vulnerabilities in CKEditor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities are possible if Drupal is configured to allow
  use of the CKEditor library for WYSIWYG editing. An attacker that can create or edit content
  (even without access to CKEditor themselves) may be able to exploit one or more XSS
  vulnerabilities to target users with access to the WYSIWYG CKEditor, including site admins with
  privileged access.");

  script_tag(name:"affected", value:"Drupal prior to version 8.9.20, version 9.x through 9.1.13 and
  9.2.x through 9.2.8.");

  script_tag(name:"solution", value:"Update to version 8.9.20, 9.1.14, 9.2.9 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-011");

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

if (version_is_less(version: version, test_version: "8.9.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.2", test_version2: "9.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
