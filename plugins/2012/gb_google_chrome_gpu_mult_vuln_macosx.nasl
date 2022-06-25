###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_gpu_mult_vuln_macosx.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome 'GPU process' Multiple Vulnerabilities (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802716");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3047");
  script_bugtraq_id(52395);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-20 11:24:20 +0530 (Tue, 20 Mar 2012)");
  script_name("Google Chrome 'GPU process' Multiple Vulnerabilities (MAC OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48375/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52395/discuss");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/03/chrome-stable-update_10.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.79 on MAC OS X");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors when loading certain
  plug-ins and handling GPU memory.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.79 or later.");
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

if(version_is_less(version:chromeVer, test_version:"17.0.963.79")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
