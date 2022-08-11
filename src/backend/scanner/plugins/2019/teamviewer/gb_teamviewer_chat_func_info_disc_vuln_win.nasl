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

CPE = "cpe:/a:teamviewer:teamviewer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815860");
  script_version("2019-12-11T08:00:09+0000");
  script_tag(name:"last_modification", value:"2019-12-11 08:00:09 +0000 (Wed, 11 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-06 12:34:34 +0530 (Fri, 06 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2019-19362");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("TeamViewer 'Chat functionality' Information Disclosure Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  script_tag(name:"summary", value:"This host is installed with TeamViewer and
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to while using Chat functionality,
  it was observed that upon login to Teamviewer desktop application for Windows,
  it saved every communication within Windows main memory. However, while user
  logs out from account or deletes conversation history, under any such case the
  data would not be wiped from main memory.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  access sensitive information.");

  script_tag(name:"affected", value:"TeamViewe version 14.3.4730 on Windows.");

  script_tag(name:"solution", value:"Update to latest version available from vendor.
  Please see the references for more information.");

  script_xref(name:"URL", value:"http://nestedif.com/teamviewer-vulnerability-improper-session-handling-leading-to-information-disclosure-advisory/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
version = infos["version"];
location = infos["location"];

if(version == "14.3.4730")
{
  report = report_fixed_ver(installed_version: version, fixed_version: "Update to latest version", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}
exit(99);
