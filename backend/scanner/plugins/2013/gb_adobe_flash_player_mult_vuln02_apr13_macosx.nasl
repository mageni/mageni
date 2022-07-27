###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln02_apr13_macosx.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities -02 April 13 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803384");
  script_version("$Revision: 11866 $");
  script_cve_id("CVE-2013-1380", "CVE-2013-1379", "CVE-2013-1378", "CVE-2013-2555");
  script_bugtraq_id(58949, 58951, 58947, 58396);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-19 11:16:07 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -02 April 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52931");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-11.html");
  script_xref(name:"URL", value:"http://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player 10.3.183.68 and earlier, and 11.x to 11.6.602.180 on
  Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Error when initializing certain pointer arrays.

  - Integer overflow error.");
  script_tag(name:"solution", value:"Upgrade to version 10.3.183.75 or 11.7.700.169.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/products/flash.html");
  exit(0);
}


include("version_func.inc");

playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!playerVer){
  exit(0);
}

if(version_is_less_equal(version:playerVer, test_version:"10.3.183.68") ||
   version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.6.602.180"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
