###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_apr10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Google Chrome Multiple Vulnerabilities (win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801312");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1228", "CVE-2010-1229", "CVE-2010-1230", "CVE-2010-1231",
                "CVE-2010-1232", "CVE-2010-1233", "CVE-2010-1234", "CVE-2010-1235",
                "CVE-2010-1236", "CVE-2010-1237");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities (win)");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=37061");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/03/stable-channel-update.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, and can cause other
  attacks.");
  script_tag(name:"affected", value:"Google Chrome version prior to 4.1.249.1036 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in handling 'SVG' document.

  - Multiple race conditions in the 'sandbox' infrastructure.

  - An error in 'sandbox' infrastructure which does not properly use pointers.

  - An error in proceesing of 'HTTP' headers, processes HTTP headers before
    invoking the SafeBrowsing feature.

  - not having the expected behavior for attempts to delete Web SQL
    Databases and clear the 'Strict Transport Security (STS)' state.

  - An error in processing of 'HTTP Basic Authentication dialog'.

  - Multiple integer overflows errors when processing 'WebKit JavaScript'
    objects.

  - not properly restricting cross-origin operations, which has unspecified
    impact and remote attack vectors.");
  script_tag(name:"solution", value:"Upgrade to the version 4.1.249.1036 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Google Chrome Web Browser and is prone to
  multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

if(version_is_less(version:gcVer, test_version:"4.1.249.1036")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
