###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_nov12_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - Nov2012 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802490");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-5117", "CVE-2012-5116", "CVE-2012-5128", "CVE-2012-5127",
                "CVE-2012-5126", "CVE-2012-5125", "CVE-2012-5124", "CVE-2012-5123",
                "CVE-2012-5122", "CVE-2012-5121", "CVE-2012-5119");
  script_bugtraq_id(56413);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-09 11:27:22 +0530 (Fri, 09 Nov 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Nov2012 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51210/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/11/stable-channel-release-and-beta-channel.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 23.0.1271.64 on Windows");
  script_tag(name:"insight", value:"- An integer overflow error exists in WebP handling.

  - An error in v8 can be exploited to cause an out-of-bounds array access.

  - Multiple use-after-free error exists in SVG filter, video layout, extension
    tab and plug-in placeholder, handling.

  - An error exists related to integer boundary checks within GPU command
    buffers.

  - An error exists related to inappropriate loading of SVG sub resource in
    'img' context.

  - A race condition error exists in Pepper buffer handling.

  - A type casting error exists in certain input handling.

  - An error in Skia can be exploited to cause an out-of-bounds read.

  - An error in texture handling can be exploited to corrupt memory.

  - An error in v8 can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 23.0.1271.64 or later.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"23.0.1271.64")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
