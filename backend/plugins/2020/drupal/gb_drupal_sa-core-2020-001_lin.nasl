# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.143612");
  script_version("2020-03-19T08:21:07+0000");
  script_tag(name:"last_modification", value:"2020-03-19 14:04:12 +0000 (Thu, 19 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-19 05:39:32 +0000 (Thu, 19 Mar 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2020-9281");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal 8.x CKEditor Vulnerability (SA-CORE-2020-001) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Drupal is prone to a cross-site scripting vulnerabilitu in third-party library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal project uses the third-party library CKEditor, which has released a
  security improvement that is needed to protect some Drupal configurations.

  Vulnerabilities are possible if Drupal is configured to use the WYSIWYG CKEditor for your site's users. When
  multiple people can edit content, the vulnerability can be used to execute XSS attacks against other people,
  including site admins with more access.");

  script_tag(name:"affected", value:"Drupal 8.7.x and 8.8.x.");

  script_tag(name:"solution", value:"Update to version 8.7.12, 8.8.4 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2020-001");
  script_xref(name:"URL", value:"https://ckeditor.com/blog/CKEditor-4.14-with-Paste-from-LibreOffice-released/#security-issues-fixed");

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

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.8.0", test_version2: "8.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
