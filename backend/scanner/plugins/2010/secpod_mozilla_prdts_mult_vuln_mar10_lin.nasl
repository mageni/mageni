###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_mult_vuln_mar10_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities Mar-10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902150");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0167", "CVE-2010-0169", "CVE-2010-0171");
  script_bugtraq_id(38918);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities Mar-10 (Linux)");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=534082");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-12.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-14.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service,
  potentially execute arbitrary code or compromise a user's system.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.3

  Thunderbird version prior to 3.0.2

  Firefox version 3.0.x before 3.0.18, 3.5.x before 3.5.8 and 3.6.x before 3.6.2");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in 'toolkit/components/passwordmgr/src/nsLoginManagerPrompter.js'
  in the asynchronous Authorization Prompt implementation it does not properly
  handle concurrent authorization requests from multiple web sites.

  - An error in browser engine allows attackers to cause a denial of service
  via vectors related to

  - 'layout/generic/nsBlockFrame.cpp' and

  - '_evaluate function in modules/plugin/base/src/nsNPAPIPlugin.cpp'

  - An error in performing cross-origin keystroke capture, and possibly conduct
  cross-site scripting (XSS) attacks, by using the addEventListener and
  setTimeout functions in conjunction with a wrapped object.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.18, 3.5.8, 3.6.2 or later

  Upgrade to Seamonkey version 2.0.3 or later

  Upgrade to Thunderbird version 3.0.2 or later");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.7") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.17") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
       exit(0);
     }
}

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"3.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
