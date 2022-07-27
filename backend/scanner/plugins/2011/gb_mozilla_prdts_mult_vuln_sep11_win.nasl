###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_sep11_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Products Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802150");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2981", "CVE-2011-2984", "CVE-2011-2378");
  script_bugtraq_id(49218, 49219, 49214);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45666/");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely
  result in denial-of-service conditions.");
  script_tag(name:"affected", value:"SeaMonkey version 2.0 through 2.2
  Mozilla Firefox version before 3.6.20
  Thunderbird version 3.0 through 3.1.11");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in the 'event-management' implementation, which fails to select
    the context for script to run in.

  - Improper handling of the dropping of a tab element.

  - An error in 'appendChild()' function, which fails to handle DOM objects.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/seamonkey/thunderbird
  and is prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.20 or later, Upgrade to SeaMonkey version to 2.3 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.6.20")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  if(version_in_range(version:seaVer, test_version:"2.0", test_version2:"2.2"))
  {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  if(version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.1.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
