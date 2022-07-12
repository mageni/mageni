###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_apr15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities - 01 Apr15 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805464");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-3044", "CVE-2015-3043", "CVE-2015-3042", "CVE-2015-3041",
                "CVE-2015-3040", "CVE-2015-3039", "CVE-2015-3038", "CVE-2015-0360",
                "CVE-2015-0359", "CVE-2015-0357", "CVE-2015-0356", "CVE-2015-0355",
                "CVE-2015-0354", "CVE-2015-0353", "CVE-2015-0352", "CVE-2015-0351",
                "CVE-2015-0350", "CVE-2015-0349", "CVE-2015-0348", "CVE-2015-0347",
                "CVE-2015-0346", "CVE-2015-0358");
  script_bugtraq_id(74065, 74062, 74068, 74064, 74067, 74066, 74069);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-20 12:39:25 +0530 (Mon, 20 Apr 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Apr15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified double free vulnerabilities.

  - An overflow condition that is triggered as user-supplied input is not
  properly validated.

  - Improper restriction of discovery of memory addresses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service, execute arbitrary code, bypass the ASLR
  protection mechanism via unspecified vectors and allow local users to gain
  privileges .");

  script_tag(name:"affected", value:"Adobe Flash Player versions before
  13.0.0.281 and 14.x through 17.x before 17.0.0.169 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.281 or 17.0.0.169 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.281"))
{
  fix = "13.0.0.281";
  VULN = TRUE;
}

if(version_in_range(version:playerVer, test_version:"14.0", test_version2:"17.0.0.168"))
{
  fix = "17.0.0.169";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
