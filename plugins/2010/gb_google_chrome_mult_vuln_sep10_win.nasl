###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Google Chrome multiple vulnerabilities (Windows) Sep10
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801447");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3246", "CVE-2010-3247", "CVE-2010-3249", "CVE-2010-3248",
                "CVE-2010-3250", "CVE-2010-3252", "CVE-2010-3251", "CVE-2010-3253",
                "CVE-2010-3255", "CVE-2010-3254", "CVE-2010-3257", "CVE-2010-3256",
                "CVE-2010-3258", "CVE-2010-3259");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities (Windows) Sep10");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=12156");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/09/stable-and-beta-channel-updates.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause denial of service
  and possibly have unspecified other impact via unknown vectors.");
  script_tag(name:"affected", value:"Google Chrome version prior to 6.0.472.53 on windows");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer to the links below.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 6.0.472.53 or later.");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to multiple
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

if(version_is_less(version:chromeVer, test_version:"6.0.472.53")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
