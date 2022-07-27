###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_mult_vuln_feb10_lin01.nasl 12653 2018-12-04 15:31:25Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.902127");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3988", "CVE-2010-0160", "CVE-2010-0162");
  script_bugtraq_id(38289, 38285, 38288);
  script_name("Mozilla Products Multiple Vulnerabilities feb-10 (Linux)");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl", "gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to potentially execute arbitrary
  code or compromise a user's system.");

  script_tag(name:"affected", value:"Seamonkey version prior to 2.0.3

  Firefox version 3.0.x before 3.0.18 and 3.5.x before 3.5.8 on Linux.");

  script_tag(name:"insight", value:"- An error exists in the implementation of Web Worker array data types when
  processing posted messages. This can be exploited to corrupt memory and potentially execute arbitrary code.

  - An error exists in the implementation of the 'showModalDialog()' function,
  can be exploited to potentially execute arbitrary JavaScript code in the
  context of a domain calling the affected function with external parameters.

  - An error exists when processing SVG documents served with a Content-Type of
  'application/octet-stream', can be exploited to execute arbitrary JavaScript
  code in the context of a domain hosting the SVG document.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Seamonkey and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.18 or 3.5.8 or later

  Upgrade to Seamonkey version 2.0.3 or later");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37242");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0405");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-05.html");

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

smVer = get_kb_item("Firefox/Linux/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"2.0.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
