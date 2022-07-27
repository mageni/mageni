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
  script_oid("1.3.6.1.4.1.25623.1.0.145266");
  script_version("2021-01-28T03:42:45+0000");
  script_tag(name:"last_modification", value:"2021-01-28 11:06:40 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 03:32:56 +0000 (Thu, 28 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2021-21615");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.276, < 2.263.3 Arbitrary File Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl");
  script_mandatory_keys("jenkins/detected");

  script_tag(name:"summary", value:"Jenkins is prone to an arbitrary file read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to a time-of-check to time-of-use (TOCTOU) race condition, the file
  browser for workspaces, archived artifacts, and $JENKINS_HOME/userContent/ follows symbolic links to
  locations outside the directory being browsed in Jenkins.");

  script_tag(name:"impact", value:"The vulnerability allows attackers with Job/Workspace permission and the
  ability to control workspace contents, e.g., with Job/Configure permission or the ability to change SCM
  contents, to create symbolic links that allow them to access files outside workspaces using the workspace browser.");

  script_tag(name:"affected", value:"Jenkins version 2.275 and prior and 2.263.2 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.276, 2.263.3 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-01-26/#SECURITY-2197");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_full(cpe: CPE, port: port))
  exit(0);

if(!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if(get_kb_item("jenkins/" + port + "/is_lts")) {
  if(version_is_less(version: version, test_version: "2.263.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.263.3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if(version_is_less(version: version, test_version: "2.276")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.276", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
