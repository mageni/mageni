# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143438");
  script_version("2020-02-04T11:07:38+0000");
  script_tag(name:"last_modification", value:"2020-02-04 11:07:38 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 03:40:37 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-2099");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.214, < 2.204.2 LTS Authentication Bypass Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to an inbound TCP Agent Protocol/3 authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins includes support for the Inbound TCP Agent Protocol/3 for
  communication between master and agents. While this protocol has been deprecated in 2018 and was recently
  removed from Jenkins in 2.214, it could still easily be enabled in Jenkins LTS 2.204.1, 2.213, and older.

  This protocol incorrectly reuses encryption parameters which allow an unauthenticated remote attacker to
  determine the connection secret. This secret can then be used to connect attacker-controlled Jenkins agents to
  the Jenkins master.");

  script_tag(name:"affected", value:"Jenkins version 2.213 and prior and 2.204.1 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.214, 2.204.2 LTS or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2020-01-29/#SECURITY-1682");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port))
  exit(0);

if (!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less(version: version, test_version: "2.204.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.204.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.214")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.214", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
