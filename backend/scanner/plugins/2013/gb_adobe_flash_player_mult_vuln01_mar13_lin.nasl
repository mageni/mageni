###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_mar13_lin.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities -01 March13 (Linux)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803324");
  script_version("$Revision: 11866 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-04 18:54:31 +0530 (Mon, 04 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0648", "CVE-2013-0643", "CVE-2013-0504");
  script_bugtraq_id(58186, 58185, 58184);
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 March13 (Linux)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028210");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52374");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.61 and earlier, and 11.x to 11.2.202.270
  on Linux");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - A flaw in the ExternalInterface ActionScript feature.

  - Firefox sandbox does not restrict privileges.

  - Buffer overflow in the Flash Player broker service.");
  script_tag(name:"solution", value:"Update to version 10.3.183.67 or 11.2.202.273.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/products/flash.html");
  exit(0);
}


include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!playerVer){
  exit(0);
}

if(version_is_less_equal(version:playerVer, test_version:"10.3.183.61") ||
   version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.2.202.270"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
