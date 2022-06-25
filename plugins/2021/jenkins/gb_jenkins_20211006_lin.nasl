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
  script_oid("1.3.6.1.4.1.25623.1.0.146872");
  script_version("2021-10-08T08:43:41+0000");
  script_tag(name:"last_modification", value:"2021-10-08 11:46:07 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-08 08:32:06 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2014-3577");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.303.2, < 2.315 HTTP Library Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to a vulnerability in the bundled version of
  commons-httpclient library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins bundles a version of the commons-httpclient library
  with the vulnerability CVE-2014-3577 that incorrectly verified SSL/TLS certificates, making it
  susceptible to man-in-the-middle attacks.

  This library is widely used as a transitive dependency in Jenkins plugins.");

  script_tag(name:"affected", value:"Jenkins version 2.314 and prior and 2.303.1 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.315, 2.303.2 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-10-06/");

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
  if(version_is_less(version: version, test_version: "2.303.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.303.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if(version_is_less(version: version, test_version: "2.315")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.315", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
