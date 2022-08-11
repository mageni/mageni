###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_use_after_free_vuln_lin.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Google Chrome Use-After-Free Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901191");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-1059");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome Use-After-Free Vulnerability (Linux)");
  script_xref(name:"URL", value:"https://bugs.webkit.org/show_bug.cgi?id=52819");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=70315");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/dev-channel-update_17.html");

  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 11.0.672.2 on Linux");
  script_tag(name:"insight", value:"An use-after-free error in WebCore in WebKit allows user-assisted remote
  attackers to cause a denial of service or possibly have unspecified other
  impact via vectors that entice a user to resubmit a form, related to improper
  handling of provisional items by the HistoryController component.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 11.0.672.2 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to use-after-free
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

if(version_is_less(version:chromeVer, test_version:"11.0.672.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
