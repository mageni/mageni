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

CPE = "cpe:/a:limesurvey:limesurvey";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142168");
  script_version("2019-04-29T05:57:09+0000");
  script_tag(name:"last_modification", value:"2019-04-29 05:57:09 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 12:23:38 +0000 (Tue, 26 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-9960");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.16.1 Relative Path Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"The downloadZip function in application/controllers/admin/export.php in
LimeSurvey allows a relative path.");

  script_tag(name:"impact", value:"An attacker might download arbitrary files.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to LimeSurvey version 3.16.1 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/1ed10d3c423187712b8f6a8cb2bc9d5cc3b2deb8");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/blob/master/docs/release_notes.txt");

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

if (version_is_less(version: version, test_version: "3.16.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.16.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);