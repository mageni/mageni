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
  script_oid("1.3.6.1.4.1.25623.1.0.148329");
  script_version("2022-06-24T06:47:37+0000");
  script_tag(name:"last_modification", value:"2022-06-24 06:47:37 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 06:41:49 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-34175");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins 2.335 < 2.356 Information Disclosure Vulnerability (SECURITY-2777) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins uses the Stapler web framework to render its UI views.
  These views are frequently composed of several view fragments, enabling plugins to extend
  existing views with more content.

  Before SECURITY-534 was fixed in Jenkins 2.186 and LTS 2.176.2, attackers could in some cases
  directly access a view fragment containing sensitive information, bypassing any permission checks
  in the corresponding view.

  In Jenkins 2.335 through 2.355 (both inclusive), the protection added for SECURITY-534 is
  disabled for some views. As a result, attackers could in very limited cases directly access a
  view fragment containing sensitive information, bypassing any permission checks in the
  corresponding view.");

  script_tag(name:"affected", value:"Jenkins version 2.335 prior to 2.356.");

  script_tag(name:"solution", value:"Update to version 2.356 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2022-06-22/#SECURITY-2777");

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

if (!get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_in_range_exclusive(version: version, test_version_lo: "2.335", test_version_up: "2.356")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.356", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
