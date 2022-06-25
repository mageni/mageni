###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su10-007.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X v10.6.4 Multiple Vulnerabilities (2010-007)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802144");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2010-1828", "CVE-2010-1829", "CVE-2010-1830", "CVE-2009-0796",
                "CVE-2010-0408", "CVE-2010-0434", "CVE-2010-1842", "CVE-2010-1831",
                "CVE-2010-1832", "CVE-2010-1833", "CVE-2010-4010", "CVE-2010-1752",
                "CVE-2010-1834", "CVE-2010-1836", "CVE-2010-1837", "CVE-2010-2941",
                "CVE-2010-1838", "CVE-2010-1840", "CVE-2010-0105", "CVE-2010-1841",
                "CVE-2008-4546", "CVE-2009-3793", "CVE-2010-0209", "CVE-2010-1297",
                "CVE-2010-2160", "CVE-2010-2161", "CVE-2010-2162", "CVE-2010-2163",
                "CVE-2010-2164", "CVE-2010-2165", "CVE-2010-2166", "CVE-2010-2167",
                "CVE-2010-2169", "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2172",
                "CVE-2010-2173", "CVE-2010-2174", "CVE-2010-2175", "CVE-2010-2176",
                "CVE-2010-2177", "CVE-2010-2178", "CVE-2010-2179", "CVE-2010-2180",
                "CVE-2010-2181", "CVE-2010-2182", "CVE-2010-2183", "CVE-2010-2184",
                "CVE-2010-2185", "CVE-2010-2186", "CVE-2010-2187", "CVE-2010-2189",
                "CVE-2010-2188", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215",
                "CVE-2010-2216", "CVE-2010-2884", "CVE-2010-3636", "CVE-2010-3638",
                "CVE-2010-3639", "CVE-2010-3640", "CVE-2010-3641", "CVE-2010-3642",
                "CVE-2010-3643", "CVE-2010-3644", "CVE-2010-3645", "CVE-2010-3646",
                "CVE-2010-3647", "CVE-2010-3648", "CVE-2010-3649", "CVE-2010-3650",
                "CVE-2010-3652", "CVE-2010-3654", "CVE-2010-3976", "CVE-2010-0001",
                "CVE-2009-2624", "CVE-2010-1844", "CVE-2010-1845", "CVE-2010-1811",
                "CVE-2010-1846", "CVE-2010-1847", "CVE-2010-1848", "CVE-2010-1849",
                "CVE-2010-1850", "CVE-2009-2473", "CVE-2009-2474", "CVE-2010-1843",
                "CVE-2010-0211", "CVE-2010-0212", "CVE-2010-1378", "CVE-2010-3783",
                "CVE-2010-0397", "CVE-2010-2531", "CVE-2010-2484", "CVE-2010-3784",
                "CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-3785",
                "CVE-2010-3786", "CVE-2010-3787", "CVE-2010-3788", "CVE-2010-3789",
                "CVE-2010-3790", "CVE-2010-3791", "CVE-2010-3792", "CVE-2010-3793",
                "CVE-2010-3794", "CVE-2010-3795", "CVE-2010-3796", "CVE-2010-1803",
                "CVE-2010-3797", "CVE-2010-0205", "CVE-2010-3798", "CVE-2009-0946",
                "CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500",
                "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2805", "CVE-2010-2806",
                "CVE-2010-2807", "CVE-2010-2808", "CVE-2010-3053", "CVE-2010-3054",
                "CVE-2011-1417", "CVE-2010-1205", "CVE-2010-2249", "CVE-2011-1290",
                "CVE-2011-1344");
  script_bugtraq_id(44812, 44799, 46832, 46849, 46822, 41174, 44803, 44832,
                    44802, 44805, 44729, 41049, 44811, 44806, 44808, 44530,
                    31537, 40809, 42363, 40586, 40779, 40781, 40801, 40803,
                    40780, 40782, 40783, 40802, 40807, 40789, 40784, 40795,
                    40800, 40805, 40785, 40787, 40788, 40790, 40808, 40791,
                    40792, 40794, 40793, 40796, 40806, 40786, 40797, 40799,
                    40798, 42364, 49303, 42361, 42362, 43205, 44691, 44693,
                    44692, 44675, 44677, 44678, 44679, 44680, 44681, 44682,
                    44683, 44684, 44685, 44686, 44687, 44504, 44671, 37886,
                    37888, 44813, 44819, 43076, 44822, 44840, 40109, 40100,
                    40106, 36080, 36079, 44784, 41770, 44831, 41770, 44833,
                    38708, 41991, 44835, 44794, 44792, 44790, 44789, 44794,
                    44792, 44814, 44834, 44829, 38478, 44828, 34550, 41663,
                    42285, 42624, 42621, 46832, 41174, 46849, 46822);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X v10.6.4 Multiple Vulnerabilities (2010-007)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4435");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024723");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Jul/msg00003.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Mar/msg00000.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Apr/msg00004.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[0-5]\.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, obtain potentially sensitive information or cause
  a denial-of-service condition.");
  script_tag(name:"affected", value:"AFP Server

  Apache mod_perl

  Apache

  AppKit

  ATS

  CFNetwork

  CoreGraphics

  CoreText

  CUPS

  Flash Player plug-in

  gzip

  Image Capture

  ImageIO

  Image RAW

  MySQL

  neon

  OpenLDAP

  OpenSSL

  Password Server

  PHP

  python

  Apple iWork

  Apple Safari

  Apple iTunes

  QuickLook

  QuickTime

  Wiki Server

  xar

  X11

  Time Machine

  WebKit Open Source");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2010-007");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.5 Update/Mac OS X Security Update 2010-007");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

osName = get_kb_item( "ssh/login/osx_name" );
if( ! osName ) exit( 0 );

osVer = get_kb_item( "ssh/login/osx_version" );
if( ! osVer ) exit( 0 );

if( "Mac OS X" >< osName && "Server" >!< osName ) {
  if( version_is_less_equal( version:osVer, test_version:"10.5.8" ) ||
      version_in_range( version:osVer, test_version:"10.6.0", test_version2:"10.6.4" ) ) {
    if( isosxpkgvuln( fixed:"com.apple.pkg.update.security.", diff:"2010.007" ) ) {
      report = report_fixed_ver( installed_version:osName + " " + osVer, fixed_version:"Install the missing security update 2010.007" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

if( "Mac OS X Server" >< osName ) {
  if( version_is_less_equal( version:osVer, test_version:"10.5.8" ) ||
      version_in_range( version:osVer, test_version:"10.6", test_version2:"10.6.4" ) ) {
    if( isosxpkgvuln( fixed:"com.apple.pkg.update.security.", diff:"2010.007" ) ) {
      report = report_fixed_ver( installed_version:osName + " " + osVer, fixed_version:"Install the missing security update 2010.007" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}
