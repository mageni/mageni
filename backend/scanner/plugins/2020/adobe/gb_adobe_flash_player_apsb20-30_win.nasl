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

CPE = "cpe:/a:adobe:flash_player";
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817152");
  script_version("2020-06-12T07:11:22+0000");
  script_cve_id("CVE-2020-9633");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-12 09:20:35 +0000 (Fri, 12 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-10 08:52:23 +0530 (Wed, 10 Jun 2020)");
  script_name("Adobe Flash Player Security Updates(apsb20-30)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before 32.0.0.387 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  32.0.0.387 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb20-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"32.0.0.387"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"32.0.0.387", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
