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
  script_oid("1.3.6.1.4.1.25623.1.0.143439");
  script_version("2020-02-04T04:20:55+0000");
  script_tag(name:"last_modification", value:"2020-02-04 04:20:55 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 03:55:43 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-2100", "CVE-2020-2101", "CVE-2020-2102", "CVE-2020-2103", "CVE-2020-2104", "CVE-2020-2105");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.219, < 2.204.2 LTS Multiple vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to multiple vulnerabilities:

  - UDP amplification reflection attack (CVE-2020-2100)

  - Non-constant time comparison of inbound TCP agent connection secret (CVE-2020-2101)

  - Non-constant time HMAC comparison (CVE-2020-2102)

  - Diagnostic page exposed session cookies (CVE-2020-2103)

  - Memory usage graphs accessible to anyone with Overall/Read (CVE-2020-2104)

  - Jenkins REST APIs vulnerable to clickjacking (CVE-2020-2105)");

  script_tag(name:"affected", value:"Jenkins version 2.218 and prior and 2.204.1 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.219, 2.204.2 LTS or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2020-01-29/");

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
  if (version_is_less(version: version, test_version: "2.219")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.219", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
