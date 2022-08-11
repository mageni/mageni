###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su11-001.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X v10.6.6 Multiple Vulnerabilities (2011-001)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902470");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-0172", "CVE-2010-1452", "CVE-2010-2068", "CVE-2011-0173",
                "CVE-2011-0174", "CVE-2011-0175", "CVE-2011-0176", "CVE-2011-0177",
                "CVE-2010-0405", "CVE-2011-0178", "CVE-2010-3434", "CVE-2010-4260",
                "CVE-2010-4261", "CVE-2010-4479", "CVE-2011-0179", "CVE-2011-0180",
                "CVE-2011-0170", "CVE-2011-0181", "CVE-2011-0191", "CVE-2011-0192",
                "CVE-2011-0194", "CVE-2011-0193", "CVE-2011-0190", "CVE-2010-1323",
                "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021", "CVE-2011-0182",
                "CVE-2011-0183", "CVE-2010-4008", "CVE-2010-4494", "CVE-2010-3089",
                "CVE-2006-7243", "CVE-2010-2950", "CVE-2010-3709", "CVE-2010-3710",
                "CVE-2010-4409", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-4150",
                "CVE-2011-0184", "CVE-2011-1417", "CVE-2011-0186", "CVE-2010-4009",
                "CVE-2010-3801", "CVE-2011-0187", "CVE-2010-3802", "CVE-2011-0188",
                "CVE-2010-3069", "CVE-2010-3315", "CVE-2011-0189", "CVE-2010-3814",
                "CVE-2010-3855", "CVE-2010-3870", "CVE-2010-4150");
  script_bugtraq_id(46988, 41963, 40827, 46984, 46987, 46991, 46971, 46994, 43331,
                    46989, 43555, 45152, 45152, 45152, 46993, 46982, 46659, 46996,
                    46657, 46658, 46973, 46972, 47023, 45118, 45116, 45117, 45122,
                    46997, 46990, 44779, 45617, 43187, 44951, 44718, 43926, 45119,
                    44723, 44718, 44980, 46965, 46832, 46995, 45241, 45240, 46992,
                    45239, 46966, 43212, 43678, 44643, 44214, 44605, 44980);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X v10.6.6 Multiple Vulnerabilities (2011-001)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Mar/msg00006.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[0-6]\.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"X11,

  ATS,

  PHP,

  HFS,

  Ruby,

  Samba,

  bzip2,

  Kernel,

  AirPort,

  Apache,

  ClamAV,

  Mailman,

  Libinfo,

  libxml,

  ImageIO,

  Kerberos,

  CoreText,

  Terminal,

  Installer,

  QuickLook,

  QuickTime,

  Image RAW,

  Subversion,

  CarbonCore,

  AppleScript,

  File Quarantine");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mac OS X 10.6.7 or Run Mac Updates and update the Security
  Update 2011-001");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.6 Update/Mac OS X Security Update 2011-001.");

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

if( "Mac OS X" >< osName || "Mac OS X Server" >< osName ) {
  if( version_is_less_equal( version:osVer, test_version:"10.5.8" ) ||
      version_in_range( version:osVer, test_version:"10.6", test_version2:"10.6.6" ) ) {
    if( isosxpkgvuln( fixed:"com.apple.pkg.update.security.", diff:"2011.001" ) ) {
      report = report_fixed_ver( installed_version:osName + " " + osVer, fixed_version:"Install the missing security update 2011.001" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );