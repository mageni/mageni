###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_vuln_feb10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Firefox Multiple Vulnerabilities Feb-10 (Windows)
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900742");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0648", "CVE-2010-0654");
  script_name("Firefox Multiple Vulnerabilities Feb-10 (Windows)");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=32309");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to obtain sensitive information via
  a crafted document.");
  script_tag(name:"affected", value:"Firefox version prior to 3.6 on Windows.");
  script_tag(name:"insight", value:"- The malformed stylesheet document and cross-origin loading of CSS
    stylesheets even when the stylesheet download has an incorrect MIME type.

  - IFRAME element allows placing the site&qts URL in the HREF attribute of a
    stylesheet 'LINK' element, and then reading the 'document.styleSheets[0].href'
    property value.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.");
  script_tag(name:"summary", value:"The host is installed with Firefox Browser and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(isnull(ffVer)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.6")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
