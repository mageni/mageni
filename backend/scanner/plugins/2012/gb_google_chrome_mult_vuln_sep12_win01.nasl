###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep12_win01.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - Sep12 (Windows-01)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802972");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-2888", "CVE-2012-2887", "CVE-2012-2886", "CVE-2012-2885",
                "CVE-2012-2884", "CVE-2012-2883", "CVE-2012-2882", "CVE-2012-2881",
                "CVE-2012-2880", "CVE-2012-2879", "CVE-2012-2878", "CVE-2012-2877",
                "CVE-2012-2876", "CVE-2012-2875", "CVE-2012-2889", "CVE-2012-2890",
                "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2894",
                "CVE-2012-2895", "CVE-2012-2874");
  script_bugtraq_id(55676);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-28 12:49:03 +0530 (Fri, 28 Sep 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Sep12 (Windows-01)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50759/");
  script_xref(name:"URL", value:"https://code.google.com/p/chromium/issues/detail?id=137852");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to conduct cross-site
  scripting attacks, bypass certain security restrictions, cause
  denial-of-service conditions and other attacks are also possible.");
  script_tag(name:"affected", value:"Google Chrome version prior to 22.0.1229.79 on Windows");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer to the links below.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 22.0.1229.79 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"22.0.1229.79")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
