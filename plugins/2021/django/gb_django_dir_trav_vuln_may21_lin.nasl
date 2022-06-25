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

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145920");
  script_version("2021-05-07T07:06:34+0000");
  script_tag(name:"last_modification", value:"2021-05-07 10:50:52 +0000 (Fri, 07 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-07 06:51:14 +0000 (Fri, 07 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-31542");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 2.2 < 2.2.21, 3.1 < 3.1.9, 3.2 < 3.2.1 Directory Traversal Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"MultiPartParser, UploadedFile, and FieldFile allow
  directory-traversal via uploaded files with suitably crafted file names.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1");

  script_tag(name:"solution", value:"Update to version 2.2.21, 3.1.9, 3.2.1 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/may/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.21", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.9", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "3.2.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
