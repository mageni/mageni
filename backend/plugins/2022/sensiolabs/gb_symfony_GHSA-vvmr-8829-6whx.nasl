# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147583");
  script_version("2022-02-02T06:19:05+0000");
  script_tag(name:"last_modification", value:"2022-02-02 11:01:49 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-02 06:11:37 +0000 (Wed, 02 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2022-23601");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony 5.3.14, 5.4.3, 6.0.3 CSRF Vulnerability (GHSA-vvmr-8829-6whx)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a missing cross-site request forgery (CSRF)
  token vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Symfony form component provides a CSRF protection mechanism
  by using a random token injected in the form and using the session to store and control the token
  submitted by the user.

  When using the FrameworkBundle, this protection can be enabled or disabled with the
  configuration. If the configuration is not specified, by default, the mechanism is enabled as
  long as the session is enabled.

  In a recent change in the way the configuration is loaded, the default behavior has been dropped
  and, as a result, the CSRF protection is not enabled in form when not explicitly enabled, which
  makes the application sensible to CSRF attacks.");

  script_tag(name:"affected", value:"Symfony version 5.3.14, 5.4.3 and 6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.3.15, 5.4.4, 6.0.4 or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-vvmr-8829-6whx");

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

if (version_is_equal(version: version, test_version: "5.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "6.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
