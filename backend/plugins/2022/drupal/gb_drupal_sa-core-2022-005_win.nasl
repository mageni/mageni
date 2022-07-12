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
  script_oid("1.3.6.1.4.1.25623.1.0.113845");
  script_version("2022-03-18T10:11:59+0000");
  script_tag(name:"last_modification", value:"2022-03-18 10:11:59 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-18 08:49:54 +0000 (Fri, 18 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-24728", "CVE-2022-24729");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities in Third-party Library (SA-CORE-2022-005) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drupal_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities in a third-party
  library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities are possible if Drupal is configured to allow
  use of the CKEditor library for WYSIWYG editing. An attacker that can create or edit content (even
  without access to CKEditor themselves) may be able to exploit one or more Cross-Site Scripting
  (XSS) vulnerabilities to target users with access to the WYSIWYG CKEditor, including site admins
  with privileged access.

  For more information, see CKEditor's security advisories linked in the references:

  - CVE-2022-24728: HTML processing vulnerability allowing to execute JavaScript code

  - CVE-2022-24729: Regular expression Denial of Service in dialog plugin");

  script_tag(name:"affected", value:"Drupal version 8.x and 9.x.");

  script_tag(name:"solution", value:"Update to version 9.2.15, 9.3.8 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2022-005");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-4fc4-4p5g-6w89");
  script_xref(name:"URL", value:"https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-f6rf-9m92-x2hh");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "9.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3", test_version_up: "9.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
