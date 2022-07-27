###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_may10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Google Chrome Multiple Vulnerabilities Windows - May10
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
  script_oid("1.3.6.1.4.1.25623.1.0.800770");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:36:02 +0200 (Fri, 07 May 2010)");
  script_cve_id("CVE-2010-1664", "CVE-2010-1663", "CVE-2010-1665");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities Windows - May10");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39651");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1016");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/04/stable-update-bug-and-security-fixes.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  and potentially compromise a user's system.");
  script_tag(name:"affected", value:"Google Chrome version prior to 4.1.249.1064");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - unspecified error while handling HTML5 media and fonts, which can be exploited
    to cause a memory corruption via unknown vectors.

  - unspecified error in Google URL, which allows to bypass the same origin policy
    via unspecified vectors.");
  script_tag(name:"solution", value:"Upgrade to the version 4.1.249.1064");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Google Chrome Web Browser and is prone
  to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

if(version_is_less(version:gcVer, test_version:"4.1.249.1064")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
