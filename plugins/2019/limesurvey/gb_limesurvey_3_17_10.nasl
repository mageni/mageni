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
  script_oid("1.3.6.1.4.1.25623.1.0.142831");
  script_version("2019-09-02T07:37:42+0000");
  script_tag(name:"last_modification", value:"2019-09-02 07:37:42 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-02 07:15:14 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2019-15640");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 3.17.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/installed");

  script_tag(name:"summary", value:"Limesurvey is prone to an input validation and multiple XSS vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - XSS with constructor statements in textedit.

  - Limesurvey does not validate both the MIME type and file extension of an image (CVE-2019-15640).

  - XSS when use Predefined label sets.

  - XSS in label title.

  - XSS in Boxes.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 3.17.10.");

  script_tag(name:"solution", value:"Update to LimeSurvey version 3.17.10 or later.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/0479e3ff93ff1473a25c71e83cc011920b072b4c#diff-d539f3f8185667ee48db78e1bf65a3b4R42-R47");

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

if (version_is_less(version: version, test_version: "3.17.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.17.10", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
