###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_xss_vuln_win_jun11.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# Adobe Products Unspecified Cross-Site Scripting Vulnerability June-2011 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802206");
  script_version("$Revision: 12006 $");
  script_cve_id("CVE-2011-2107");
  script_bugtraq_id(48107);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_name("Adobe Products Unspecified Cross-Site Scripting Vulnerability June-2011 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player, Adobe Reader or Acrobat and is
prone to cross-site scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of certain unspecified input, which
allows remote attackers to inject arbitrary web script or HTML via unspecified
vectors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site.");
  script_tag(name:"affected", value:"Adobe Flash Player versions prior to 10.3.181.22 on Windows.

Adobe Reader and Acrobat X versions 10.0.3 and prior on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.181.22 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-13.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl", "secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:flash_player";
if(flashVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:flashVer, test_version:"10.3.181.22")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less_equal(version:readerVer, test_version:"10.0.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_less_equal(version:acrobatVer, test_version:"10.0.3")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
exit(0);
