###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_exec_vuln_win_jun10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Products Remote Code Execution Vulnerability - jun10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801360");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-1297");
  script_bugtraq_id(40586);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Products Remote Code Execution Vulnerability - jun10 (Windows)");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1349");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1348");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa10-01.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code by tricking a user into opening a specially crafted PDF file.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.x to 9.3.2

  Adobe Flash Player version 9.0.x to 9.0.262 and 10.x to 10.0.45.2");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption error in the 'authplay.dll'
  library and 'SWF' file when processing ActionScript Virtual Machine 2 (AVM2)
  'newfunction' instructions within Flash content in a PDF document.");

  script_tag(name:"summary", value:"This host is installed with Adobe products and is prone to
  remote code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to Adobe Flash Player 10.1.53.64 or 9.0.277.0 or later

  For Adobe Reader additional updates has been released which are described in the referenced advisories.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(pVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  #  Adobe Flash Player version 9.0.0 to 9.0.262 and 10.x to 10.0.45.2
  if(version_in_range(version:pVer, test_version:"9.0.0", test_version2:"9.0.262") ||
     version_in_range(version:pVer, test_version:"10.0", test_version2:"10.0.45.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:acVer, test_version:"9.0", test_version2:"9.3.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";
if(arVer = get_app_version(cpe:CPE))
{
  if(version_in_range(version:arVer, test_version:"9.0", test_version2:"9.3.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
