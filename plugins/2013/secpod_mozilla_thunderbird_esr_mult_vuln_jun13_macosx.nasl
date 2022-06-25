###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_thunderbird_esr_mult_vuln_jun13_macosx.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Mozilla Thunderbird ESR Multiple Vulnerabilities - June 13 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.903221");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                 "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                 "CVE-2013-1697", "CVE-2013-1692");
  script_bugtraq_id(60766, 60773, 60774, 60777, 60778, 60783, 60787, 60776, 60784,
                    60765);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-26 18:40:17 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities - June 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53970");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028702");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird-ESR/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible.");
  script_tag(name:"affected", value:"Thunderbird ESR version 17.x before 17.0.7 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - PreserveWrapper does not handle lack of wrapper.

  - Error in processing of SVG format images with filters to read pixel values.

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.

  - XrayWrapper does not properly restrict use of DefaultValue for method calls.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird ESR 17.0.7 or later.");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird");
  script_tag(name:"summary", value:"This host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

tbVer = get_kb_item("ThunderBird-ESR/MacOSX/Version");
if(tbVer && tbVer =~ "^17\.0")
{
  if(version_in_range(version:tbVer, test_version:"17.0", test_version2:"17.0.6"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
