###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_unspecified_vuln.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Firefox Unspecified Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902027");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2010-1028");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability (Windows)");


  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Mozilla Firefox 3.6 and prior");
  script_tag(name:"insight", value:"The flaw is caused by unspecified errors and unknown attack vectors.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later");
  script_tag(name:"summary", value:"The host is running Mozilla Firefox and is prone to unspecified
  vulnerability.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38608");
  script_xref(name:"URL", value:"http://www.h-online.com/security/news/item/Zero-day-exploit-for-Firefox-3-6-936124.html");
  script_xref(name:"URL", value:"http://blog.psi2.de/en/2010/02/20/going-commercial-with-firefox-vulnerabilities/comment-page-1/#comment-666");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/upgrade.html");
  exit(0);
}


include("version_func.inc");

foxVer = get_kb_item("Firefox/Win/Ver");
if(!foxVer){
  exit(0);
}

if(version_is_less_equal(version:foxVer, test_version:"3.6")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
