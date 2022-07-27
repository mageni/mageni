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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817806");
  script_version("2020-10-15T06:59:23+0000");
  script_cve_id("CVE-2020-9746");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-15 11:08:37 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-14 08:49:58 +0530 (Wed, 14 Oct 2020)");
  script_name("Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (apsb20-58) - Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a null pointer
  dereference error.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 32.0.0.445
  within Microsoft Edge or Internet Explorer on:

  Windows 10 Version 1607 for x32/x64 Edition

  Windows 10 Version 1703 for x32/x64 Edition

  Windows 10 Version 1709 for x32/x64 Edition

  Windows 10 Version 1803 for x32/x64 Edition

  Windows 10 Version 1809 for x32/x64 Edition

  Windows 10 Version 1903 for x32/x64 Edition

  Windows 10 Version 1909 for x32/x64 Edition

  Windows 10 Version 2004 for x32/x64 Edition

  Windows 10 x32/x64 Edition

  Windows 8.1 for x32/x64 Edition

  Windows Server 2012/2012 R2

  Windows Server 2016

  Windows Server 2019");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 32.0.0.445 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb20-58.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");

  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1, win2016:1, win2019:1) <= 0)
  exit(0);

cpe_list = make_list("cpe:/a:adobe:flash_player_internet_explorer", "cpe:/a:adobe:flash_player_edge");
if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(path) {
  path += "\Flashplayerapp.exe";
} else {
  path = "Could not find the install location";
}

if(version_is_less(version:vers, test_version:"32.0.0.445")) {
  report = report_fixed_ver(file_checked:path, file_version:vers, vulnerable_range:"Less than 32.0.0.445");
  security_message(data:report);
  exit(0);
}

exit(99);
