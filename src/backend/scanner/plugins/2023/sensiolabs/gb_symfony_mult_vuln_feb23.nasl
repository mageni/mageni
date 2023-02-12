# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.126332");
  script_version("2023-02-07T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-02-07 10:08:49 +0000 (Tue, 07 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-06 09:11:37 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-24894", "CVE-2022-24895");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symfony Multiple Vulnerabilities (GHSA-h7vf-5wrv-9fhv, GHSA-3gv2-29qc-v67m)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-24894: If the Symfony HTTP cache system is enabled, header might be stored and
  returned to some other clients. An attacker can use this to retrieve the victim's session.

  - CVE-2022-24895: When authenticating users Symfony by default regenerates the session ID upon
  login, but preserves the rest of session attributes. Because this does not clear CSRF tokens upon
  login, this might enables same-site attackers to bypass the CSRF protection mechanism by
  performing an attack similar to a session-fixation.");

  script_tag(name:"affected", value:"Symfony version 2.0.0 prior to 4.4.50, 5.0.0 prior to
  5.4.20, 6.0.0 prior to 6.0.20, 6.1.0 prior to 6.1.12 and 6.2.0 prior to 6.2.6.");

  script_tag(name:"solution", value:"Update to version 4.4.50, 5.4.20, 6.0.20, 6.1.12, 6.2.6
  or later.");

  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-h7vf-5wrv-9fhv");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-3gv2-29qc-v67m");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "4.4.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.50", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.4.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1.0", test_version_up: "6.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.2.0", test_version_up: "6.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
