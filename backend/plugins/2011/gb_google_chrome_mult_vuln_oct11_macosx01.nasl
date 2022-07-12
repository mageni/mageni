###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_oct11_macosx01.nasl 11997 2018-10-20 11:59:41Z mmartin $
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
  script_oid("1.3.6.1.4.1.25623.1.0.802264");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_cve_id("CVE-2011-2845", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877",
                "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881",
                "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885",
                "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889",
                "CVE-2011-3890", "CVE-2011-3891");
  script_bugtraq_id(50360);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome multiple vulnerabilities - October11 (Mac OS X)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026242");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  steal cookie-based authentication credentials, bypass the cross-origin
  restrictions, perform spoofing attacks, and disclose potentially sensitive
  information, other attacks may also be possible.");
  script_tag(name:"affected", value:"Google Chrome version prior to 15.0.874.102 on Mac OS X");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 15.0.874.102 or later.");
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

if(version_is_less(version:chromeVer, test_version:"15.0.874.102")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
