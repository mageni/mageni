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
  script_oid("1.3.6.1.4.1.25623.1.0.147112");
  script_version("2021-11-10T03:03:45+0000");
  script_tag(name:"last_modification", value:"2021-11-10 03:03:45 +0000 (Wed, 10 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 06:48:12 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-08 17:33:00 +0000 (Mon, 08 Nov 2021)");

  script_cve_id("CVE-2021-21685", "CVE-2021-21686", "CVE-2021-21687", "CVE-2021-21688",
                "CVE-2021-21689", "CVE-2021-21690", "CVE-2021-21691", "CVE-2021-21692",
                "CVE-2021-21693", "CVE-2021-21694", "CVE-2021-21695", "CVE-2021-21696",
                "CVE-2021-21697");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.303.3, < 2.319 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-21685, CVE-2021-21686, CVE-2021-21687, CVE-2021-21688, CVE-2021-21689, CVE-2021-21690,
  CVE-2021-21691, CVE-2021-21692, CVE-2021-21693, CVE-2021-21694, CVE-2021-21695: Bypassing path
  filtering of agent-to-controller access control

  - CVE-2021-21696: Agent-to-controller access control allowed writing to sensitive directory used
  by Pipeline: Shared Groovy Libraries Plugin

  - CVE-2021-21697: Agent-to-controller access control allows reading/writing most content of build
  directories");

  script_tag(name:"affected", value:"Jenkins version 2.318 and prior and 2.303.2 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.319, 2.303.3 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2021-11-04/");

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
  if (version_is_less(version: version, test_version: "2.303.3")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.303.3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "2.319")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.319", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
