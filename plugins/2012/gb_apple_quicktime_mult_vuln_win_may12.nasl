###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_win_may12.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802795");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0663", "CVE-2012-0665", "CVE-2011-3458", "CVE-2011-3459",
                "CVE-2012-0658", "CVE-2012-0659", "CVE-2012-0666", "CVE-2011-3460",
                "CVE-2012-0667", "CVE-2012-0661", "CVE-2012-0668", "CVE-2012-0669",
                "CVE-2012-0670", "CVE-2012-0671", "CVE-2012-0265", "CVE-2012-0664",
                "CVE-2012-0660");
  script_bugtraq_id(53571, 53576, 51809, 51811, 53465, 53467, 53577, 51814,
                    53583, 53466, 53579, 53580, 53469, 53574, 53584, 53578,
                    53469);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-18 13:04:18 +0530 (Fri, 18 May 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities - (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5261");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47447/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027065");
  script_xref(name:"URL", value:"http://prod.lists.apple.com/archives/security-announce/2012/May/msg00005.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"QuickTime Player version prior to 7.7.2 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - Errors within the handling of TeXML files.

  - An error when handling of text tracks and MPEG files and sean atoms.

  - An error while handling RLE, JPEG2000, H.264 and Sorenson encoded
    movie files.

  - An error exists within the parsing of MP4 encoded files and .pict files.

  - An off-by-one error can be exploited to cause a single byte buffer overflow.

  - An error when handling audio samples.

  - An error within the plugin's handling of QTMovie objects.

  - An error when parsing the MediaVideo header in videos encoded with the PNG
    format.

  - A signedness error within the handling of QTVR movie files.

  - A boundary error in QuickTime.qts when extending a file path based on its
    short path.");
  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.7.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple QuickTime and is prone to
  multiple vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.apple.com/downloads/");
  exit(0);
}

include("version_func.inc");

quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

if(version_is_less(version:quickVer, test_version:"7.7.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
