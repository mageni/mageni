# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146201");
  script_version("2021-07-01T06:27:14+0000");
  script_tag(name:"last_modification", value:"2021-07-01 10:12:29 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-01 06:19:31 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-21670", "CVE-2021-21671");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.289.2, < 2.300 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-21670: Improper permission checks allow canceling queue items and aborting builds

  - CVE-2021-21671: Session fixation");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - cancel queue items and abort builds of jobs for which they have Item/Cancel permission even
  when they do not have Item/Read permission.

  - use social engineering techniques to gain administrator access to Jenkins");

  script_tag(name:"affected", value:"Jenkins version 2.299 and prior and 2.289.1 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.300, 2.289.2 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-06-30/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(get_kb_item("jenkins/" + port + "/is_lts")) {
  if(version_is_less(version: version, test_version: "2.289.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.289.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if(version_is_less(version: version, test_version: "2.300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.300", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
