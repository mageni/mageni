###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_dos_vuln_aug10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801255");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-0209", "CVE-2010-2213", "CVE-2010-2215",
                "CVE-2010-2214", "CVE-2010-2216");
  script_bugtraq_id(42341);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Windows)");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  cause denial-of-service conditions, or perform click-jacking attacks.");

  script_tag(name:"affected", value:"Adobe AIR version prior to 2.0.3

  Adobe Flash Player before 9.0.280 and 10.x before 10.1.82.76 on windows");

  script_tag(name:"insight", value:"The flaws are due to memory corruptions and click-jacking issue via
  unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to Adobe  Air 2.0.3 and Adobe Flash Player 9.0.280 or 10.1.82.76 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://get.adobe.com/air");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(playerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:playerVer, test_version:"9.0.280") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.1.82.75"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:adobe_air";
if(airVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:airVer, test_version:"2.0.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
