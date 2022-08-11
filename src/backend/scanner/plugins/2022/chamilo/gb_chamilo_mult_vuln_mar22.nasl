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

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124043");
  script_version("2022-04-13T07:52:40+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 16:47:25 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-38745", "CVE-2021-40662");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS < 1.11.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-38745: Zero-click code injection

  - CVE-2021-40662: Remote code execution (RCE)

  - Multiple CSRF, XSS, path traversal, SQL injection, RCE, file upload, SSRF, command injection,
  LFI, information disclosure, privilege escalation vulnerabilities (issues 44 - 86)");

  script_tag(name:"affected", value:"Chamilo version 1.11.14 and prior.");

  script_tag(name:"solution", value:"Update to version 1.11.16 or later.");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-83-2021-08-11-High-impact-Moderate-risk-Cross-Site-Request-Forgery-CSRF-leading-to-Remote-Code-Execution");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-81-2021-07-26-High-impact-Low-risk-Zero-Code-RCE-in-admin");
  script_xref(name:"URL", value:"https://11.chamilo.org/documentation/changelog.html#1.11.16");

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

if (version_is_less(version: version, test_version: "1.11.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
