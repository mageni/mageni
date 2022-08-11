###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_mar09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities - Mar09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800359");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0522");
  script_bugtraq_id(33890);
  script_name("Adobe Flash Player Multiple Vulnerabilities - Mar09 (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34012");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause remote code
  execution, compromise system privileges or may cause exposure of sensitive information.");

  script_tag(name:"affected", value:"Adobe Flex version 3.x or 2.x

  Adobe AIR version prior to 1.5.1

  Adobe Flash CS3/CS4 Professional

  Adobe Flash Player 9 version prior to 9.0.159.0

  Adobe Flash Player 10 version prior to 10.0.22.87");

  script_tag(name:"insight", value:"- Error while processing multiple references to an unspecified object which
  can be exploited by tricking the user to accessing a malicious crafted SWF file.

  - Input validation error in the processing of SWF file.

  - Error while displaying the mouse pointer on Windows which may cause 'Clickjacking' attacks.");

  script_tag(name:"summary", value:"This host is installed with Adobe Products and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution", value:"Update to version 1.5.1 for Adobe Air.

  Update to Adobe Flash Player 9.0.159.0 or 10.0.22.87 and Adobe CS3/CS4, Flex 3.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:playerVer, test_version:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0",
                                         test_version2:"10.0.22.86"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:airVer, test_version:"1.5.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
