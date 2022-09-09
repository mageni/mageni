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
  script_oid("1.3.6.1.4.1.25623.1.0.127170");
  script_version("2022-09-07T10:10:59+0000");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-01 10:39:07 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2013-7330", "CVE-2014-2059", "CVE-2014-2067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 1.551, < 1.532.2 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2013-7330: A remote authenticated users are able to configure an otherwise restricted
  project via vectors related to post-build actions.

  - CVE-2014-2059: CLI job creation had a directory traversal vulnerability. This allows a
  malicious user with a limited set of permissions to overwrite files in the controller and
  escalate privileges.

  - CVE-2014-2067: A malicious user with a certain set of permissions can cause Jenkins to store
  arbitrary HTML fragment which may lead to stored cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"Jenkins prior to version 1.551, Jenkins LTS prior to version
  1.532.2.");

  script_tag(name:"solution", value:"Update to version 1.551, 1.532.2 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2014-02-14/");

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
  if (version_is_less(version: version, test_version: "1.532.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.532.2", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less(version: version, test_version: "1.551")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.551", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
