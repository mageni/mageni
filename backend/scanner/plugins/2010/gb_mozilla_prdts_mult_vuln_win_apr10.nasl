###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_apr10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities Apr-10 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800753");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0173", "CVE-2010-0182");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities Apr-10 (Windows)");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57388");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57396");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-16.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-24.html");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to to cause a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.4,

  Thunderbird version proior to 3.0.4 and

  Firefox version before 3.5.9 and 3.6.x before 3.6.2");

  script_tag(name:"insight", value:"The flaws are due to:

  - A memory corruption error when user loads specially crafted HTML or specially
  crafted HTML-based e-mail, which allows to execute arbitrary code via unknown vectors.

  - An error in 'XMLDocument::load()' method. It is not checking 'nsIContentPolicy'
  during loading of content by XML documents, which allows to bypass intended
  access restrictions via crafted content.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.9, 3.6.2

  Upgrade to Seamonkey version 2.0.4

  Upgrade to Thunderbird version 3.0.4");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.4"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"3.0.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
