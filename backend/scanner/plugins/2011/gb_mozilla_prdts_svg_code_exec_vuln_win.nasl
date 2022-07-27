###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_svg_code_exec_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Mozilla Products 'SVG' Code Execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802147");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-0084");
  script_bugtraq_id(49213);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products 'SVG' Code Execution Vulnerability (Windows)");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=730519");
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
  Thunderbird version 3.0 through 3.1.11
  Mozilla Firefox version before 3.6.20 and 4.x through 5.0.1");
  script_tag(name:"insight", value:"The flaw is due to error in 'SVGTextElement.getCharNumAtPosition'
  function, which fails to properly handle SVG text.");
  script_tag(name:"summary", value:"The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to arbitrary code execution vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.20 or 6.0 or later, Upgrade to SeaMonkey version to 2.3 or later,
  Upgrade to Thunderbird version to 3.1.12 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"3.6.20")||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"5.0.1"))
  {
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
