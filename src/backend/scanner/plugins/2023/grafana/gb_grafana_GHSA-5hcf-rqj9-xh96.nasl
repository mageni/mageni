# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149215");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-30 07:25:31 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2022-41912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 6.3.0-beta1 < 8.5.16, 9.x < 9.2.8, 9.3.0 < 9.3.2 SAML Privilege Escalation Vulnerability (GHSA-5hcf-rqj9-xh96)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a privilege escalation vulnerability via
  SAML.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Grafana Enterprise is using crewjam/saml library for SAML
  integration. On Nov 30, 2022 an advisory and relevant fix was published in the upstream library,
  which described a vulnerability allowing privilege escalation when processing SAML responses
  containing multiple assertions.

  The vulnerability is possible to exploit only when a SAML document is not signed and multiple
  assertions are being used, where at least one assertion is signed. As a result, an attacker could
  intercept the SAML response and add any unsigned assertion, which would be parsed as signed by
  the library.");

  script_tag(name:"affected", value:"Grafana version 6.3.0-beta1 through 9.3.1.");

  script_tag(name:"solution", value:"Update to version 8.5.16, 9.2.8, 9.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-5hcf-rqj9-xh96");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.3.0", test_version_up: "8.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0", test_version_up: "9.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
