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
  script_oid("1.3.6.1.4.1.25623.1.0.146220");
  script_version("2021-07-05T06:53:41+0000");
  script_tag(name:"last_modification", value:"2021-07-05 06:53:41 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-05 06:52:41 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2021-35042");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 3.1 < 3.1.13, 3.2 < 3.2.5 SQLi Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"insight", value:"Unsanitized user input passed to QuerySet.order_by() could
  bypass intended column reference validation in path marked for deprecation resulting in a
  potential SQL injection even if a deprecation warning is emitted.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django version 3.1 prior to 3.1.13 and 3.2 prior to 3.2.5");

  script_tag(name:"solution", value:"Update to version 3.1.13, 3.2.5 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/jul/01/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.13", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2.0", test_version2: "3.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
