# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112837");
  script_version("2020-11-11T10:30:12+0000");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 09:13:11 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-25267", "CVE-2020-25268");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_detect.nasl");
  script_mandatory_keys("ilias/installed");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Authenticated stored cross-site scripting (XSS) (CVE-2020-25267)

  - Authenticated remote code execution (CVE-2020-25268)");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  gain code execution or inject arbitrary script code into an affected site.");

  script_tag(name:"affected", value:"ILIAS through version 6.4.");

  script_tag(name:"solution", value:"Update to version 6.5 or later.");

  script_xref(name:"URL", value:"https://medium.com/bugbountywriteup/exploiting-ilias-learning-management-system-4eda9e120620");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
