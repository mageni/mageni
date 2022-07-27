###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_apr13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 April 2013 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803358");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0916", "CVE-2013-0917", "CVE-2013-0918", "CVE-2013-0920",
                "CVE-2013-0921", "CVE-2013-0922", "CVE-2013-0923", "CVE-2013-0924",
                "CVE-2013-0925", "CVE-2013-0926");
  script_bugtraq_id(58723, 58724, 58725, 58728, 58729, 58730, 58731, 58732,
                    58733, 58734);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-02 12:24:45 +0530 (Tue, 02 Apr 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 April 2013 (Windows)");
  script_xref(name:"URL", value:"http://www.dhses.ny.gov/ocs/advisories/2013/2013-034.cfm");
  script_xref(name:"URL", value:"http://energy.gov/cio/articles/v-121-google-chrome-multiple-vulnerabilities");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_26.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the browser, bypass security restrictions, cause
  denial-of-service condition or possibly have unspecified other impact.");
  script_tag(name:"affected", value:"Google Chrome versions prior to 26.0.1410.43 on Windows");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 26.0.1410.43 or later.");
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

if(version_is_less(version:chromeVer, test_version:"26.0.1410.43"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
