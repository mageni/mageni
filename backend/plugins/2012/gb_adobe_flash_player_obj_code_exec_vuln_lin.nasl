###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_obj_code_exec_vuln_lin.nasl 11973 2018-10-19 05:51:32Z cfischer $
#
# Adobe Flash Player Object Confusion Remote Code Execution Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802771");
  script_version("$Revision: 11973 $");
  script_cve_id("CVE-2012-0779");
  script_bugtraq_id(53395);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 07:51:32 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-08 13:35:54 +0530 (Tue, 08 May 2012)");
  script_name("Adobe Flash Player Object Confusion Remote Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49096/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027023");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to create crafted Flash content
  that, when loaded by the target user, will trigger an object confusion flaw
  and execute arbitrary code on the target system.");
  script_tag(name:"affected", value:"Adobe Flash Player version prior to 10.3.183.19 on Linux
  Adobe Flash Player version 11.x prior to 11.2.202.235 on Linux");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.183.19 or 11.2.202.235 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  object confusion remote code execution vulnerability.");
  script_tag(name:"insight", value:"The flaw is due to an error related to object confusion.

  NOTE: Further information is not available.");
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

if(version_is_less(version:flashVer, test_version:"10.3.183.19") ||
   version_in_range(version:flashVer, test_version:"11.0",  test_version2:"11.2.202.233")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
