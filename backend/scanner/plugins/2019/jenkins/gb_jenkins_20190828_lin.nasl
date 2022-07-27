# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142823");
  script_version("2019-08-30T04:18:39+0000");
  script_tag(name:"last_modification", value:"2019-08-30 04:18:39 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-30 04:05:10 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2019-10383", "CVE-2019-10384");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.192 and < 2.176.3 LTS Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Jenkins is prone to multiple vulnerabilities:

  - Stored XSS vulnerability in update center (CVE-2019-10383)

  - CSRF protection tokens for anonymous users does not expire in some circumstances (CVE-2019-10384)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Jenkins weekly up to and including 2.191 and Jenkins LTS up to and
  including 2.176.2");

  script_tag(name:"solution", value:"Update to version 2.176.3 LTS, 2.192 weekly or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2019-08-28/");

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
proto    = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less(version: version, test_version: "2.176.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.176.3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.192")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.192", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
