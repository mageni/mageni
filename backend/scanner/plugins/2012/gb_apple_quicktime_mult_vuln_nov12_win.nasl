###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_nov12_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803047");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-1374", "CVE-2012-3757", "CVE-2012-3751", "CVE-2012-3758",
                "CVE-2012-3752", "CVE-2012-3753", "CVE-2012-3754", "CVE-2012-3755",
                "CVE-2012-3756");
  script_bugtraq_id(56438);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-09 13:08:03 +0530 (Fri, 09 Nov 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5581");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51226");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Nov/msg00002.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow condition.");
  script_tag(name:"affected", value:"QuickTime Player version prior to 7.7.3 on Windows");
  script_tag(name:"insight", value:"- Multiple boundary errors exists when handling a PICT file, a Targa file,
    the transform attribute of 'text3GTrack' elements and the 'rnet' box
    within MP4 file.

  - Use-after-free errors exists when handling '_qtactivex_' parameters within
    an HTML object and 'Clear()' method.");
  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.7.3 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple QuickTime and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.apple.com/downloads/");
  exit(0);
}


include("version_func.inc");

quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

if(version_is_less(version:quickVer, test_version:"7.7.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
