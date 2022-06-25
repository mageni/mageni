# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144514");
  script_version("2020-09-02T07:48:55+0000");
  script_tag(name:"last_modification", value:"2020-09-02 10:05:23 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 07:40:24 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-24583", "CVE-2020-24584");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 2.2.x < 2.2.16, 3.0.x < 3.0.10, 3.1.x < 3.1.1 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Incorrect permissions on intermediate-level directories on Python 3.7+ (CVE-2020-24583)

  - Permission escalation in intermediate-level directories of the file system cache on Python 3.7+ (CVE-2020-2458)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 2.2.x, 3.0.x and 3.1.0.");

  script_tag(name:"solution", value:"Update to version 2.2.16, 3.0.10, 3.1.1 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2020/sep/01/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.16", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "3.1.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
