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
  script_oid("1.3.6.1.4.1.25623.1.0.127167");
  script_version("2022-09-07T10:10:59+0000");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-08-29 09:43:07 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 18:16:00 +0000 (Tue, 13 Apr 2021)");

  script_cve_id("CVE-2021-21639", "CVE-2021-21640");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.287, < 2.277.2 LTS Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-21639: Jenkins does not validate the type of object created after loading the data
  submitted to the config.xml REST API endpoint of a node.

  - CVE-2021-21640: Jenkins does not properly check that a newly created view has an allowed name
  allowing attackers with View/Create permission to create views with invalid or used names.");

  script_tag(name:"affected", value:"Jenkins prior to version 2.287, Jenkins LTS prior to version
  2.277.2.");

  script_tag(name:"solution", value:"Update to version 2.287, 2.277.2 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-04-07/#SECURITY-1871");
  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-04-07/#SECURITY-1721");


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
  if (version_is_less(version: version, test_version: "2.277.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.277.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.287")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.287", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
