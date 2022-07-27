###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_mult_vuln_feb10_lin.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities feb-10 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902125");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1571", "CVE-2010-0159");
  script_bugtraq_id(38287, 38286);
  script_name("Mozilla Products Multiple Vulnerabilities feb-10 (Linux)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37242");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-45/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0405");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-03.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl", "gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to potentially execute arbitrary
  code or compromise a user's system.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.3

  Thunderbird version prior to 3.0.2

  Firefox version 3.0.x before 3.0.18 and 3.5.x before 3.5.8 on Linux.");

  script_tag(name:"insight", value:"- An error exists when handling 'out-of-memory conditions', can be exploited
  to trigger a memory corruption and execute arbitrary code via a specially crafted web page.

  - An errors in 'nsBlockFrame::StealFrame()' function in 'layout/generic/nsBlockFrame.cpp', can be exploited to
  corrupt memory and potentially execute arbitrary code.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.18 or 3.5.8 or later

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
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.17"))
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
  if(version_is_less_equal(version:tbVer, test_version:"3.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
