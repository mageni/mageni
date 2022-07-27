###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_vuln_feb09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities Feb-09 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900308");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355",
                "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_bugtraq_id(33598);
  script_name("Mozilla Firefox Multiple Vulnerabilities Feb-09 (Windows)");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-06.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in bypassing certain security restrictions,
  information disclosures, JavaScript code executions which can be executed with
  the privileges of the signed users.");

  script_tag(name:"affected", value:"Firefox version 2.x to 3.0.5 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - Cookies marked 'HTTPOnly' are readable by JavaScript through the request
  calls of XMLHttpRequest methods i.e. XMLHttpRequest.getAllResponseHeaders
  and XMLHttpRequest.getResponseHeader.

  - Using local internet shortcut files to access other sites could be
  bypassed by redirecting to a privileged 'about:' URI e.g. 'about:plugins'.

  - Chrome XBL methods can be used to execute arbitrary Javascripts within the
  context of another website through the same origin policy by using
  'window.eval' method.

  - 'components/sessionstore/src/nsSessionStore.js' file does not block the
  changes of INPUT elements to type='file' during tab restoration.

  - Error in caching certain HTTP directives which is being ignored by Firefox
  which can expose sensitive data in any shared network.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.6.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"2.0", test_version2:"3.0.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
