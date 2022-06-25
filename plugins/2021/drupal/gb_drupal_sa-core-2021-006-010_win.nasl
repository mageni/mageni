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
  script_oid("1.3.6.1.4.1.25623.1.0.146714");
  script_version("2021-09-16T09:12:02+0000");
  script_tag(name:"last_modification", value:"2021-09-17 10:28:54 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-16 09:11:15 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-13673", "CVE-2020-13674", "CVE-2020-13675", "CVE-2020-13676",
                "CVE-2020-13677");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.x < 8.9.19, 9.x < 9.1.13, 9.2.x < 9.2.6 Multiple Vulnerabilities (SA-CORE-2021-006, SA-CORE-2021-007, SA-CORE-2021-008, SA-CORE-2021-009, SA-CORE-2021-010) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-13673: The Drupal core Media module allows embedding internal and external media in
  content fields. In certain circumstances, the filter could allow an unprivileged user to inject
  HTML into a page when it is accessed by a trusted user with permission to embed media. In some
  cases, this could lead to cross-site scripting.

  - CVE-2020-13674: The QuickEdit module does not properly validate access to routes, which could
  allow cross-site request forgery under some circumstances and lead to possible data integrity
  issues.

  - CVE-2020-13675: Drupal's JSON:API and REST/File modules allow file uploads through their HTTP
  APIs. The modules do not correctly run all file validation, which causes an access bypass
  vulnerability. An attacker might be able to upload files that bypass the file validation process
  implemented by modules on the site.

  - CVE-2020-13676: The QuickEdit module does not properly check access to fields in some
  circumstances, which can lead to unintended disclosure of field data.

  - CVE-2020-13677: Under some circumstances, the Drupal core JSON:API module does not properly
  restrict access to certain content, which may result in unintended access bypass.");

  script_tag(name:"affected", value:"Drupal version 8.x through 8.9.18, 9.x through 9.1.12 and
  9.2.x through 9.2.5.");

  script_tag(name:"solution", value:"Update to version 8.9.19, 9.1.13, 9.2.6 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-006");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-007");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-008");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-009");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2021-010");

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

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.9.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.9.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.2", test_version2: "9.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
