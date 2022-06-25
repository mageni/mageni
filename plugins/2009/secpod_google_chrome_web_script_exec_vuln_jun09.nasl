###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_web_script_exec_vuln_jun09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Google Chrome Web Script Execution Vulnerabilities - June09
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
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=479880");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=7338");
  script_xref(name:"URL", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name:"URL", value:"http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_cve_id("CVE-2009-2060", "CVE-2009-2071", "CVE-2009-2068");

  script_oid("1.3.6.1.4.1.25623.1.0.900370");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Web Script Execution Vulnerabilities - June09");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary web script
  in an https site's context and spoof an arbitrary https site by letting a
  browser obtain a valid certificate.");
  script_tag(name:"affected", value:"Google Chrome version through 3.0.187.1 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
    returned by a proxy server, which can exploited by sending the browser a
    valid certificate from this site during one request, and then sending the
    browser a crafted 502 response page upon a subsequent request.

  - Error exists in src/net/http/http_transaction_winhttp.cc while the HTTP
    Host header to determine the context of a document provided in a '4xx' or
    '5xx' CONNECT response from a proxy server, which can be exploited by
    modifying this CONNECT response, aka an 'SSL tampering' attack.

  - Detects http content in https web pages only when the top-level frame uses
    https. This can be exploited by modifying an http page to include an https
    iframe that references a script file on an http site, related to
    'HTTP-Intended-but-HTTPS-Loadable (HPIHSL) pages.'");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 4.1.249.1064 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host has Google Chrome installed and is prone to Web Script
  Execution vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"3.0.187.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
