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

CPE = "cpe:/a:gitea:gitea";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142305");
  script_version("2019-04-25T08:58:41+0000");
  script_tag(name:"last_modification", value:"2019-04-25 08:58:41 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-25 08:34:13 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-11228", "CVE-2019-11229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gitea < 1.7.6 or < 1.8.0-rc3 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitea_detect.nasl");
  script_mandatory_keys("gitea/detected");

  script_tag(name:"summary", value:"Gitea is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Gitea is prone to multiple vulnerabilities:

  - repo/setting.go does not validate the form.MirrorAddress before calling SaveAddress (CVE-2019-11228)

  - models/repo_mirror.go mishandles mirror repo URL settings, leading to remote code execution (CVE-2019-11229)");

  script_tag(name:"affected", value:"Gitea versions prior to 1.7.6 and 1.8.x before 1.8-rc3.");

  script_tag(name:"solution", value:"Update to version 1.7.6, 1.8-rc3 or later.");

  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.7.6");
  script_xref(name:"URL", value:"https://github.com/go-gitea/gitea/releases/tag/v1.8.0-rc3");

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

if (version_is_less(version: version, test_version: "1.7.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.8.0.rc1", test_version2: "1.8.0.rc2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.0.rc3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
