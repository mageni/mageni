###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_oct11_macosx.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Google Chrome multiple vulnerabilities - October11 (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802256");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-2876", "CVE-2011-2877", "CVE-2011-2878", "CVE-2011-2879",
                "CVE-2011-2880", "CVE-2011-2881", "CVE-2011-3873");
  script_bugtraq_id(49938);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - October11 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46308/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, cause denial-of-service conditions and bypass
  the same-origin policy.");
  script_tag(name:"affected", value:"Google Chrome version prior to 14.0.835.202 on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free error exists in text line box handling.

  - An error in the SVG text handling can be exploited to reference a stale
    font.

  - An error exists within cross-origin access handling associated with a
    window prototype.

  - Some errors exist within audio node handling related to lifetime and
    threading.

  - A use-after-free error exists in the v8 bindings.

  - An error when handling v8 hidden objects can be exploited to corrupt memory.

  - An error in the shader translator can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 14.0.835.202 or later.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
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

if(version_is_less(version:chromeVer, test_version:"14.0.835.202")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
