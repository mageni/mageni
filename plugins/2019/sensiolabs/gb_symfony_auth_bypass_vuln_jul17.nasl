# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:sensiolabs:symfony";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140108");
  script_version("2019-06-07T02:37:52+0000");
  script_tag(name:"last_modification", value:"2019-06-07 02:37:52 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-07 02:20:22 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-11365");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony Authentication Bypass Vulnerability (Jul17)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When fixing issue 23319 with 23341, a security issue was inadvertently
  introduced.

  After the 'fix', validating a user password with a UserPassword constraint but with no NotBlank constraint would
  pass without any error as previously (the empty password would not be compared with the user password).");

  script_tag(name:"affected", value:"Symfony versions 2.7.30, 2.7.31, 2.8.23, 2.8.24, 3.2.10, 3.2.11, 3.3.3 and
  3.3.4.");

  script_tag(name:"solution", value:"Update to version 2.7.32, 2.8.25, 3.2.12, 3.3.5 or later.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2017-11365-empty-passwords-validation-issue");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "2.7.30", test_version2: "2.7.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.32", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.8.23", test_version2: "2.8.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.25", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2.10", test_version2: "3.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.12", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3.3", test_version2: "3.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
