###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_arbitrary_code_exec_vuln_nov10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Products Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801477");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_cve_id("CVE-2010-3654");
  script_bugtraq_id(44504);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Products Content Code Execution Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41917");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/298081");
  script_xref(name:"URL", value:"http://contagiodump.blogspot.com/2010/10/potential-new-adobe-flash-player-zero.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  code in the context of the user running the affected application.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.x to 9.4 on Windows
  Adobe Flash Player version 10.1.85.3 and prior on Windows");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error which can be
  exploited to execute arbitrary code.");

  script_tag(name:"summary", value:"This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
  installed, and is prone to arbitrary code execution vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.1.102.64 or later

  Upgrade to Adobe Reader/Acrobat version 9.4.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:readerVer, test_version:"9.0.0", test_version2:"9.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:acrobatVer, test_version:"9.0.0", test_version2:"9.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:flash_player";
if(flashVer = get_app_version(cpe:CPE))
{
  if(version_is_less_equal(version:flashVer, test_version:"10.1.85.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
