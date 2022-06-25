###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_mult_vuln01_feb14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities - 01 Feb14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903338");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0498", "CVE-2014-0499", "CVE-2014-0502");
  script_bugtraq_id(65704, 65703, 65702);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-24 18:04:57 +0530 (Mon, 24 Feb 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Feb14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to multiple unspecified and a double free error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, disclose potentially
sensitive information and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.7.700.269 and 11.8.x through 12.0.x
before 12.0.0.70 on Windows");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.269 or 12.0.0.70 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57057");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
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

if(version_is_less(version:playerVer, test_version:"11.7.700.269") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"12.0.0.69"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
