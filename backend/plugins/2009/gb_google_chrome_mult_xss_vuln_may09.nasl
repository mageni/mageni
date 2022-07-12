###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_xss_vuln_may09.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Google Chrome Multiple XSS Vulnerabilities (May 09)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800561");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-1412", "CVE-2009-1340");
  script_bugtraq_id(34704);
  script_name("Google Chrome Multiple XSS Vulnerabilities (May 09)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34900");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9860");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/04/stable-update-security-fix.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes and
  XSS attack in the context of the web browser.");
  script_tag(name:"affected", value:"Google Chrome versions prior to 1.0.154.59.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Error in chromeHTML URL protocol handler, that do not satisfy the
    IsWebSafeScheme restriction via a web page that sets document.location
    and also that are not constructed with sufficient escaping hence when
    invoked by Internet Explorer might open multiple tabs for unconstrained
    protocols such as javascript: or file:.

  - It may allow malicious URLs to bypass the same-origin policy and
    obtain sensitive information including authentication credentials.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 1.0.154.59.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to
  multiple XSS vulnerabilities.");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"1.0.154.59")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
