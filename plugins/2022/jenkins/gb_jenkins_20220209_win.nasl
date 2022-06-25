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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147622");
  script_version("2022-02-10T03:57:46+0000");
  script_tag(name:"last_modification", value:"2022-02-10 11:02:19 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 03:57:07 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-43859", "CVE-2022-0538");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.319.3, < 2.334 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is affected by the XStream library's vulnerability
  CVE-2021-43859. This library is used by Jenkins to serialize and deserialize various XML files,
  like global and job config.xml, build.xml, and numerous others.

  This allows attackers able to submit crafted XML files to Jenkins to be parsed as configuration,
  e.g. through the POST config.xml API, to cause a denial of service (DoS).");

  script_tag(name:"affected", value:"Jenkins version 2.333 and prior and 2.319.2 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.334, 2.319.3 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2022-02-09/");

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
  if (version_is_less(version: version, test_version: "2.319.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.319.3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.334")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.334", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
