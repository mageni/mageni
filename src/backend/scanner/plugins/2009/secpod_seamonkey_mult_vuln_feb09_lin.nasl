###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Seamonkey Multiple Vulnerabilities Feb-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900313");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0356",
                "CVE-2009-0357");
  script_bugtraq_id(33598);
  script_name("Mozilla Seamonkey Multiple Vulnerabilities Feb-09 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33808");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in bypassing certain security
  restrictions, information disclosures, JavaScript code executions which
  can be executed with the privileges of the signed users.");
  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.15 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Vectors related to the layout engine and destruction of arbitrary layout
    objects by the 'nsViewManager::Composite' function.

  - Cookies marked 'HTTPOnly' are readable by JavaScript through the request
    calls of XMLHttpRequest methods i.e. XMLHttpRequest.getAllResponseHeaders
    and XMLHttpRequest.getResponseHeader.");
  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.15.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Seamonkey browser and is prone
  to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(!smVer)
  exit(0);

if(version_is_less(version:smVer, test_version:"1.1.15")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
