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

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147590");
  script_version("2022-02-04T02:20:30+0000");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-04 02:11:55 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-22818", "CVE-2022-23833");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 2.2.27, 3.x < 3.2.12, 4.x < 4.0.2 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-22818: Possible cross-site scripting (XSS) via {% debug %} template tag

  - CVE-2022-23833: Denial of service (DoS) possibility in file uploads");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django prior to version 2.2.27, version 3.x through 3.2.11 and
  version 4.x through 4.0.1.");

  script_tag(name:"solution", value:"Update to version 2.2.27, 3.2.12, 4.0.2 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2022/feb/01/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.2.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.27", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.12", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
