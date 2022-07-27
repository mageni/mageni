###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln2_apr12_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-02 - April 12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802837");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3066", "CVE-2011-3067", "CVE-2011-3068", "CVE-2011-3069",
                "CVE-2011-3070", "CVE-2011-3071", "CVE-2011-3072", "CVE-2011-3073",
                "CVE-2011-3074", "CVE-2011-3075", "CVE-2011-3076", "CVE-2011-3077",
                "CVE-2012-0724", "CVE-2012-0725");
  script_bugtraq_id(52913, 52914, 52916);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-18 12:25:47 +0530 (Wed, 18 Apr 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-02 - April 12 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48732/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026892");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/04/stable-and-beta-channel-updates.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 18.0.1025.151 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - Unspecified errors in flash player, allows to corrupt memory in the
    chrome interface.

  - An out of bounds read error when handling skia clipping.

  - Errors in the cross origin policy when handling iframe replacement and
    parenting pop up windows.

  - Multiple use after free errors when handling line boxes, v8 bindings,
    HTMLMediaElement, SVG resources, media content, focus events and when
    applying style commands.

  - A read after free error in the script bindings.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 18.0.1025.151 or later.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"18.0.1025.151")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
