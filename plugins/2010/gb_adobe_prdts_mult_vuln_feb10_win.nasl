###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_feb10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - feb10 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800475");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0186", "CVE-2010-0187");
  script_bugtraq_id(38198, 38200);
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities -feb10 (Windows)");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=563819");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass security
  restrictions.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 1.5.3.9130

  Adobe Flash Player 10 version prior to 10.0.45.2 on Windows");

  script_tag(name:"insight", value:"Cross domain vulnerabilities present in Adobe Flash Player/Adobe Air allows
  remote attackers to bypass intended sandbox restrictions and make cross-domain requests via unspecified vectors.");

  script_tag(name:"solution", value:"Update to Adobe Air 1.5.3.9130 or Adobe Flash Player 10.0.45.2.");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.45.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:airVer, test_version:"1.5.3.9130")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
