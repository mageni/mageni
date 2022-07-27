###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep12_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - Sep12 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802451");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-2869", "CVE-2012-2868", "CVE-2012-2867", "CVE-2012-2866",
                "CVE-2012-2865", "CVE-2012-2872", "CVE-2012-2871", "CVE-2012-2870");
  script_bugtraq_id(55331);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-03 14:01:42 +0530 (Mon, 03 Sep 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Sep12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50447");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55331");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/08/stable-channel-update_30.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 21.0.1180.89 on Windows");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Out-of-bounds read in line breaking

  - Bad cast with run-ins.

  - Browser crash with SPDY.

  - Race condition with workers and XHR.

  - Avoid stale buffer in URL loading.

  - Lower severity memory management issues in XPath

  - Bad cast in XSL transforms.

  - XSS in SSL interstitial.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 21.0.1180.89 or later.");
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

if(version_is_less(version:chromeVer, test_version:"21.0.1180.89")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
