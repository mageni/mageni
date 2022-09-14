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
  script_oid("1.3.6.1.4.1.25623.1.0.148713");
  script_version("2022-09-12T10:18:03+0000");
  script_tag(name:"last_modification", value:"2022-09-12 10:18:03 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-12 04:18:53 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:35:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-2048");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins HTTP/2 DoS Vulnerability (CVE-2022-2048) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to an HTTP/2 denial of service (DoS)
  vulnerability in Jetty.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins bundles Winstone-Jetty, a wrapper around Jetty, to act
  as HTTP and servlet server when started using java -jar jenkins.war. This is how Jenkins is run
  when using any of the installers or packages, but not when run using servlet containers such as
  Tomcat.

  Jenkins bundle versions of Jetty affected by the security vulnerability CVE-2022-2048. This
  vulnerability allows unauthenticated attackers to make the Jenkins UI unresponsive by exploiting
  Jetty's handling of invalid HTTP/2 requests, causing a denial of service.");

  script_tag(name:"affected", value:"Jenkins version 2.346.3 (LTS) and prior and 2.362 and prior.");

  script_tag(name:"solution", value:"Update to version 2.361.1 (LTS), 2.363 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2022-09-09/");

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
  if (version_is_less_equal(version: version, test_version: "2.346.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.361.1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.363")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.363", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
