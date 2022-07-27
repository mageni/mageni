# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:jenkins:jenkins';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142269");
  script_version("2019-04-17T09:17:28+0000");
  script_tag(name:"last_modification", value:"2019-04-17 09:17:28 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-17 07:53:07 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-1003049", "CVE-2019-1003050");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.164.2 LTS and < 2.172 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to multiple vulnerabilities:

  - Users who cached their CLI authentication would remain authenticated, because the fix for CVE-2019-1003004 does
    not reject existing remoting-based CLI authentication caches (CVE-2019-1003049)

  - The f:validateButton form control for the Jenkins UI does not properly escape job URLs, resulting in a
    cross-site scripting (XSS) vulnerability exploitable by users with the ability to control job names
    (CVE-2019-1003050)");

  script_tag(name:"affected", value:"Jenkins LTS 2.164.1 and prior and Jenkins weekly 2.171 and prior.");

  script_tag(name:"solution", value:"Update to version 2.164.2 (LTS) and 2.172 (weekly).");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2019-04-10/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less(version: version, test_version: "2.164.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.164.2", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
} else if (version_is_less(version: version, test_version: "2.172")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.172", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
