###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win01_apr10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Code execution vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800752");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0174", "CVE-2010-0176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Code Execution vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57393");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0748");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023776.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023781.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  system or cause the browser to crash.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.4,

  Thunderbird version prior to 3.0.4 and

  Firefox version 3.0.x before 3.0.19, 3.5.x before 3.5.9, 3.6.x before 3.6.2");

  script_tag(name:"insight", value:"The flaws are due to :

  - A memory corruption error when user loads specially crafted HTML or specially
  crafted HTML-based e-mail, which allows to execute arbitrary code via unknown
  vectors.

  - A dangling pointer flaw in the 'nsTreeContentView' when user loads specially
  crafted HTML containing '<option>' elements in an XUL tree '<optgroup>'.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone to
  Denial of Service vulnerability.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.19, 3.5.9, 3.6.2

  Upgrade to Seamonkey version 2.0.4

  Upgrade to Thunderbird version 3.0.4");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.8") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.18") ||
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
