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
  script_oid("1.3.6.1.4.1.25623.1.0.112852");
  script_version("2021-01-14T12:35:32+0000");
  script_tag(name:"last_modification", value:"2021-01-15 11:06:40 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-14 10:48:11 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-21602", "CVE-2021-21603", "CVE-2021-21604", "CVE-2021-21605",
                "CVE-2021-21606", "CVE-2021-21607", "CVE-2021-21608", "CVE-2021-21609",
                "CVE-2021-21610", "CVE-2021-21611");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.275, < 2.263.2 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Arbitrary file read vulnerability in workspace browsers (CVE-2021-21602)

  - XSS vulnerability in notification bar (CVE-2021-21603)

  - Improper handling of REST API XML deserialization errors (CVE-2021-21604)

  - Path traversal vulnerability in agent names (CVE-2021-21605)

  - Arbitrary file existence check in file fingerprints (CVE-2021-21606)

  - Excessive memory allocation in graph URLs leads to denial of service (CVE-2021-21607)

  - Stored XSS vulnerability in button labels (CVE-2021-21608)

  - Missing permission check for paths with specific prefix (CVE-2021-21609)

  - Reflected XSS vulnerability in markup formatter preview (CVE-2021-21610)

  - Stored XSS vulnerability on new item page (CVE-2021-21611)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - achieve stored and/or reflected cross-site scripting

  - inject crafted content into Old Data Monitor that results in the instantiation of potentially unsafe objects when discarded by an administrator

  - create symbolic links that allow them to access files outside workspaces using the workspace browser

  - start up the application with unsafe legacy defaults after a restart

  - check for the existence of XML files on the controller file system where the relative path can be constructed as 32 characters

  - request or have legitimate Jenkins users request crafted URLs that rapidly use all available memory in Jenkins, potentially leading to out of memory errors

  - access plugin-provided URLs without having the actual permissions to do so.");

  script_tag(name:"affected", value:"Jenkins version 2.274 and prior and 2.263.1 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.275, 2.263.2 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-01-13/");

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
  if(version_is_less(version: version, test_version: "2.263.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.263.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if(version_is_less(version: version, test_version: "2.275")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.275", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
