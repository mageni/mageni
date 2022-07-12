###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_secure_cookie_sec_bypass_vuln_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Google Chrome Secure Cookie Security Bypass Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902615");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2008-7294");
  script_bugtraq_id(49133);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Google Chrome Secure Cookie Security Bypass Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies");
  script_xref(name:"URL", value:"http://michael-coates.blogspot.com/2010/01/cookie-forcing-trust-your-cookies-no.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to overwrite or delete arbitrary
  cookies by sending a specially crafted HTTP response through a man-in-the-
  middle attack.");
  script_tag(name:"affected", value:"Google Chrome version prior to 4.0.211.0 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to improper restrictions for modifications to cookies
  established in HTTPS sessions i.e lack of the HTTP Strict Transport Security
  (HSTS) includeSubDomains feature, which allows man-in-the-middle attackers
  to overwrite or delete arbitrary cookies via a Set-Cookie header in an HTTP
  response.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 4.0.211.0 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to security bypass
  vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"4.0.211.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
