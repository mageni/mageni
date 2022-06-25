###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln01_apr13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities -01 April 13 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803381");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1383", "CVE-2013-1384", "CVE-2013-1385", "CVE-2013-1386");
  script_bugtraq_id(58980, 58982, 58983, 58984);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-19 10:32:08 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities -01 April 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52981");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-12.html");
  script_xref(name:"URL", value:"http://cert-mu.gov.mu/English/Pages/Vulnerability%20Notes/2013/VN-2013-93.aspx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause obtain
  sensitive information, remote code execution, and corrupt system memory.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Version 12.0.0.112 and prior on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Unknown errors in unspecified vectors.

  - Buffer overflow via unspecified vectors.

  - Does not prevent access to address information, which makes it easy to
    bypass the ASLR protection mechanism.");
  script_tag(name:"solution", value:"Upgrade to version 12.0.2.122 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Shockwave player and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://get.adobe.com/shockwave");
  exit(0);
}


include("version_func.inc");

playerVer = get_kb_item("Adobe/Shockwave/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_less_equal(version:playerVer, test_version:"12.0.0.112"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
