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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170354");
  script_version("2023-03-10T10:09:32+0000");
  script_tag(name:"last_modification", value:"2023-03-10 10:09:32 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-09 18:08:40 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-27898");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins XSS Vulnerability (CVE-2023-27898) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to a cross-site scripting (XSS)
  vulnerability in plugin manager.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins does not escape the Jenkins version a plugin depends on
  when rendering the error message stating its incompatibility with the current version of Jenkins in
  the plugin manager.

  This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to
  provide plugins to the configured update sites and have this message shown by Jenkins instances.");

  script_tag(name:"affected", value:"Jenkins version 2.277.1 through 2.375.3 (LTS) and 2.270 through
  2.393.");

  script_tag(name:"solution", value:"Update to version 2.375.4 (LTS), 2.394 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2023-03-08/#SECURITY-3037");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_in_range(version: version, test_version: "2.277.1", test_version2: "2.375.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.375.4", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "2.270", test_version2: "2.393")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.394", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
