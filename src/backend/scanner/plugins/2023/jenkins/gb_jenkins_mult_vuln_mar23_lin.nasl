# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170356");
  script_version("2023-03-10T10:09:32+0000");
  script_tag(name:"last_modification", value:"2023-03-10 10:09:32 +0000 (Fri, 10 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-09 18:08:40 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-27899", "CVE-2023-24998", "CVE-2023-27900", "CVE-2023-27901",
                "CVE-2023-27902", "CVE-2023-27903", "CVE-2023-27904");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.375.4 (LTS), < 2.394 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-27899: Temporary plugin file created with insecure permissions

  - CVE-2023-24998, CVE-2023-27900, CVE-2023-27901: DoS vulnerability in bundled Apache Commons
  FileUpload library

  - CVE-2023-27902: Workspace temporary directories accessible through directory browser

  - CVE-2023-27903: Temporary file parameter created with insecure permissions

  - CVE-2023-27904: Information disclosure through error stack traces related to agents");

  script_tag(name:"affected", value:"Jenkins version 2.375.3 (LTS) and prior and 2.393 and prior.");

  script_tag(name:"solution", value:"Update to version 2.375.4 (LTS), 2.394 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2023-03-08/");

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
  if (version_is_less_equal(version: version, test_version: "2.375.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.375.4", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less_equal(version: version, test_version: "2.393")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.394", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
