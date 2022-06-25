###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_font_parsing_code_exec_vuln_lin.nasl 11973 2018-10-19 05:51:32Z cfischer $
#
# Adobe Flash Player Font Parsing Code Execution Vulnerability - (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802941");
  script_version("$Revision: 11973 $");
  script_cve_id("CVE-2012-1535");
  script_bugtraq_id(55009);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:51:32 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-20 13:00:42 +0530 (Mon, 20 Aug 2012)");
  script_name("Adobe Flash Player Font Parsing Code Execution Vulnerability - (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50285/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-18.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or
  cause the application to crash and take control of the affected system.");
  script_tag(name:"affected", value:"Adobe Flash Player version 11.2.202.236 and prior on Linux");
  script_tag(name:"insight", value:"An unspecified error occurs when handling SWF content in a word document.
  This may allow a context-dependent attacker to execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 11.2.202.238 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  unspecified code execution vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

if(version_is_less_equal(version:flashVer, test_version:"11.2.202.236")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
