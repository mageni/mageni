###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_sep10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities sep-10 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801450");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-2760", "CVE-2010-2764", "CVE-2010-2766", "CVE-2010-2765",
                "CVE-2010-2768", "CVE-2010-2767", "CVE-2010-2769", "CVE-2010-3166",
                "CVE-2010-3167", "CVE-2010-3169", "CVE-2010-3168");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities sep-10 (Windows)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-51.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-57.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/firefox36.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird31.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service,
  execute arbitrary code, or cause buffer overflow.");

  script_tag(name:"affected", value:"Seamonkey version before 2.0.7

  Firefox version 3.5.x before 3.5.12 and 3.6.x before 3.6.9

  Thunderbird version 3.0.x before 3.0.7 and 3.1.x before 3.1.3");

  script_tag(name:"insight", value:"The flaws are due to:

  - Some pointer held by a 'XUL' tree selection could be freed and then later
  reused, potentially resulting in the execution of attacker-controlled memory.

  - Information leak via 'XMLHttpRequest' statusText.

  - Dangling pointer vulnerability using 'DOM' plugin array.

  - 'Frameset' integer overflow vulnerability.

  - type attribute of an '<object>' tag, which override the charset of a framed
  HTML document.

  - Dangling pointer vulnerability in the implementation of 'navigator.plugins'
    in which the navigator object could retain a pointer to the plugins array
    even after it had been destroyed.

  - Copy-and-paste or drag-and-drop into 'designMode' document allows XSS.

  - Heap buffer overflow in 'nsTextFrameUtils::TransformText'

  - Dangling pointer vulnerability in 'XUL <tree>'s content view.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey/Thunderbird that are
  prone to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.12 or 3.6.9 or later

  Upgrade to Seamonkey version 2.0.7 or later

  Upgrade to Thunderbird version 3.0.7 or 3.1.3 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.8") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.11"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"3.1", test_version2:"3.1.2") ||
     version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.0.6")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
