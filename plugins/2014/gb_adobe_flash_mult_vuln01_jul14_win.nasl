###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_mult_vuln01_jul14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities-01 July14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804714");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4671", "CVE-2014-0539", "CVE-2014-0537");
  script_bugtraq_id(68457, 68454, 68455);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-11 10:43:50 +0530 (Fri, 11 Jul 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 July14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - An error when handling JSONP callbacks.

  - Multiple Unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 13.0.0.231 and 14.x before 14.0.0.145 on
Windows.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 13.0.0.231 or 14.0.0.145 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59774");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"13.0.0.231") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"14.0.0.144"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
