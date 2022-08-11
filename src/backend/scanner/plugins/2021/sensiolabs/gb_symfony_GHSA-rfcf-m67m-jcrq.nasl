# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112907");
  script_version("2021-06-21T13:16:17+0000");
  script_tag(name:"last_modification", value:"2021-06-21 13:16:17 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-21 13:09:11 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2021-32693");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony 5.3.x < 5.3.2 Incorrect Authentication Vulnerability (GHSA-rfcf-m67m-jcrq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to an incorrect authentication vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When an application defines multiple firewalls, the authenticated
  token delivered by one of the firewalls is available to all other firewalls. This can be abused
  when the application defines different providers for different parts of an application. In such a
  situation, a user authenticated on one part of the application is considered authenticated
  on the whole application.");

  script_tag(name:"affected", value:"Symfony version 5.3.x before 5.3.2.");

  script_tag(name:"solution", value:"Update to version 5.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-rfcf-m67m-jcrq");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^5\.3\." && version_is_less(version: version, test_version: "5.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
