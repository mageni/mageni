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

CPE = "cpe:/a:django_project:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143452");
  script_version("2020-02-05T05:23:42+0000");
  script_tag(name:"last_modification", value:"2020-02-05 05:23:42 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-05 04:49:01 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-7471");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 1.11.x < 1.11.28, 2.2.x < 2.2.10, 3.0.x < 3.0.3 SQL Injection Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"Django allows SQL Injection if untrusted data is used as a StringAgg delimiter
  (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column
  delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it is
  possible to break escaping and inject malicious SQL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 1.11.x, 2.2.x and 3.0.x.");

  script_tag(name:"solution", value:"Update to version 1.11.28, 2.2.10, 3.0.3 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2020/feb/03/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "1.11.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.28", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
