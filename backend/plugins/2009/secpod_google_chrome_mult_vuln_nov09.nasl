###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - Nov09
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
  script_oid("1.3.6.1.4.1.25623.1.0.900890");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3931", "CVE-2009-3932", "CVE-2009-3933", "CVE-2009-3934");
  script_bugtraq_id(36947);
  script_name("Google Chrome Multiple Vulnerabilities - Nov09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37273/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3159");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/11/stable-channel-update.html");
  script_xref(name:"URL", value:"http://securethoughts.com/2009/11/using-blended-browser-threats-involving-chrome-to-steal-files-on-your-computer/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary JavaScript code
  and disclose the content of local files, memory corruption or CPU consumption
  and which may result in Denial of Service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 3.0.195.32 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Error in 'browser/download/download_exe.cc', which fails to display a
    warning when a user downloads and opens '.svg', '.mht' or '.xml' files.
    This can be exploited to disclose the content of local files via a
    specially crafted web page.

  - An error in the Gears SQL API implementation can be exploited to put SQL
    metadata into a bad state and cause a memory corruption.

  - An error in WebKit, which can be exploited via a web page that calls the
    JavaScript setInterval method, which triggers an incompatibility between
    the 'WTF::currentTime' and 'base::Time' functions.

  - Error in 'WebFrameLoaderClient::dispatchDidChangeLocationWithinPage' function
    in 'src/webkit/glue/webframeloaderclient_impl.cc' and which can be exploited
    via a page-local link, related to an 'empty redirect chain, ' as demonstrated
    by a message in Yahoo! Mail.");
  script_tag(name:"solution", value:"Upgrade to version 3.0.195.32 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer)
  exit(0);

if(version_is_less(version:chromeVer, test_version:"3.0.195.32")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
