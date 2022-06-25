###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_jun14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities-01 June14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804646");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0531", "CVE-2014-0532", "CVE-2014-0533", "CVE-2014-0534",
                "CVE-2014-0535", "CVE-2014-0536");
  script_bugtraq_id(67962, 67973, 67974, 67963, 67970, 67961);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-19 12:33:33 +0530 (Thu, 19 Jun 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 June14 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple Flaws exists due to,

  - Certain unspecified input is not properly sanitised before being returned to
the user.

  - An unspecified error can be exploited to bypass certain security restrictions.

  - Another unspecified error can be exploited to corrupt memory.

  - Another unspecified error can be exploited to bypass certain security
restrictions.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 13.0.0.223, 14.x before 14.0.0.125 on
Mac OS X.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 13.0.0.223 or 14.0.0.125 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"13.0.0.223") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"14.0.0.124"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
