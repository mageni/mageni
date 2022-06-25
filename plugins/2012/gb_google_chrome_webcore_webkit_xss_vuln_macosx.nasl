###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_webcore_webkit_xss_vuln_macosx.nasl 11549 2018-09-22 12:11:10Z cfischer $
#
# Google Chrome Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802498");
  script_version("$Revision: 11549 $");
  script_cve_id("CVE-2012-5851");
  script_bugtraq_id(56570);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-21 15:15:03 +0530 (Wed, 21 Nov 2012)");
  script_name("Google Chrome Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=92692");
  script_xref(name:"URL", value:"http://blog.opensecurityresearch.com/2012/09/simple-cross-site-scripting-vector-that.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass a
cross-site scripting (XSS) protection mechanism via a crafted string.");
  script_tag(name:"affected", value:"Google Chrome version 4.x to 22 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is due to 'html/parser/XSSAuditor.cpp' in WebCore in
WebKit does not consider all possible output contexts of reflected data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to cross
site scripting vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_greater_equal(version:chromeVer, test_version:"4") &&
   version_is_less(version:chromeVer, test_version:"23")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
