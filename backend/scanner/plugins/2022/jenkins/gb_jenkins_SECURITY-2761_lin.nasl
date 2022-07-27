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
  script_oid("1.3.6.1.4.1.25623.1.0.148325");
  script_version("2022-06-24T05:49:57+0000");
  script_tag(name:"last_modification", value:"2022-06-24 05:49:57 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-24 05:47:34 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2022-34171");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins 2.321 < 2.356, 2.332.1 LTS < 2.332.4 LTS XSS Vulnerability (SECURITY-2761) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The HTML output generated for new symbol-based SVG icons
  includes the title attribute of l:ionicon until Jenkins 2.334 and alt attribute of l:icon since
  Jenkins 2.335 without further escaping.");

  script_tag(name:"affected", value:"Jenkins version 2.321 prior to 2.356 and 2.332.1 LTS prior to
  2.332.4 LTS.");

  script_tag(name:"solution", value:"Update to version 2.356, 2.332.4 LTS, 2.346.1 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2022-06-22/#SECURITY-2781");

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
  if (version_in_range_exclusive(version: version, test_version_lo: "2.332.1", test_version_up: "2.332.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.332.4 / 2.346.1", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range_exclusive(version: version, test_version_lo: "2.321", test_version_up: "2.356")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.356", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
