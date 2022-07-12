###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_unspecified_vuln01_feb15_macosx.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Adobe Flash Player Unspecified Vulnerability - 01 Feb15 (Mac OS X)
#
# Authors:
# Rinu <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805443");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-0313", "CVE-2015-0314", "CVE-2015-0315", "CVE-2015-0316",
                "CVE-2015-0317", "CVE-2015-0318", "CVE-2015-0319", "CVE-2015-0320",
                "CVE-2015-0321", "CVE-2015-0322", "CVE-2015-0323", "CVE-2015-0324",
                "CVE-2015-0325", "CVE-2015-0326", "CVE-2015-0327", "CVE-2015-0328",
                "CVE-2015-0329", "CVE-2015-0330", "CVE-2015-0331");
  script_bugtraq_id(72429, 72514);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-10 11:38:12 +0530 (Tue, 10 Feb 2015)");
  script_name("Adobe Flash Player Unspecified Vulnerability - 01 Feb15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified errors due to improper validation of user-supplied input.

  - Multiple unspecified type confusion errors.

  - Multiple errors leading to overflow condition.

  - Multiple unspecified NULL pointer dereference errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to corrupt memory, dereference already freed memory, execute arbitrary
  code or have other unspecified impacts.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  13.0.0.269 and 14.x through 16.x before 16.0.0.305 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.269 or 16.0.0.305 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.269"))
{
  fix = "13.0.0.269";
  VULN = TRUE;
}

if(version_in_range(version:playerVer, test_version:"14.0", test_version2:"16.0.0.304"))
{
  fix = "16.0.0.305";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
