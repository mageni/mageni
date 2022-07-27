###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_firefox_esr_mult_vuln_jun13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Mozilla Firefox ESR Multiple Vulnerabilities - June 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903215");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                 "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                 "CVE-2013-1697", "CVE-2013-1682");
  script_bugtraq_id(60765, 60766, 60773, 60774, 60777, 60778, 60783, 60787, 60776,
                    60784);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-26 16:40:01 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - June 13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53970");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028702");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR versions 17.x before 17.0.7 on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - PreserveWrapper does not handle lack of wrapper.

  - Error in processing of SVG format images with filters to read pixel values.

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.

  - Multiple unspecified errors in the browser engine.

  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.

  - XrayWrapper does not properly restrict use of DefaultValue for method calls.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR 17.0.7 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox-ESR/Win/Ver");
if(ffVer && ffVer =~ "^17\.0")
{
  if(version_in_range(version:ffVer, test_version:"17.0", test_version2:"17.0.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
