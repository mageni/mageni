###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_feb13_lin.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities -01 Feb13 (Linux)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803406");
  script_version("$Revision: 11865 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-12 13:17:51 +0530 (Tue, 12 Feb 2013)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2013-0633", "CVE-2013-0634");
  script_bugtraq_id(57787, 57788);
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 Feb13 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52116");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81866");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause buffer overflow,
  remote code execution, and corrupt system memory.");
  script_tag(name:"affected", value:"Adobe Flash Player prior to 10.3.183.51 and 11.x prior to 11.2.202.262
  on Linux");
  script_tag(name:"insight", value:"Error while processing multiple references to an unspecified object which can
  be exploited by tricking the user to accessing a malicious crafted SWF file.");
  script_tag(name:"solution", value:"Update to version 11.2.202.262 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/products/flash.html");
  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"10.3.183.51") ||
     version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.2.202.261"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
