###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su11-004.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X v10.6.8 Multiple Vulnerabilities (2011-004)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902466");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2011-0196", "CVE-2011-0197", "CVE-2011-0198", "CVE-2011-0199",
                "CVE-2011-0200", "CVE-2011-0201", "CVE-2011-0202", "CVE-2011-0203",
                "CVE-2011-0204", "CVE-2011-0205", "CVE-2011-0206", "CVE-2011-1132",
                "CVE-2010-2632", "CVE-2011-0195", "CVE-2011-0207", "CVE-2010-3677",
                "CVE-2010-3682", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835",
                "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2009-3245",
                "CVE-2010-0740", "CVE-2010-3864", "CVE-2010-4180", "CVE-2011-0014",
                "CVE-2010-4651", "CVE-2011-0208", "CVE-2011-0209", "CVE-2011-0210",
                "CVE-2011-0211", "CVE-2010-3790", "CVE-2011-0213", "CVE-2010-3069",
                "CVE-2011-0719", "CVE-2011-0212", "CVE-2011-0715");
  script_bugtraq_id(48437, 48443, 48436, 48447, 48416, 48426, 48427, 48418, 48437,
                    48439, 48429, 48422, 43819, 47668, 48444, 42646, 42599, 43676,
                    38562, 39013, 44884, 45164, 46264, 46768, 48440, 48419, 48442,
                    48420, 44794, 48430, 43212, 46597, 46734);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X v10.6.8 Multiple Vulnerabilities (2011-004)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1338");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00000.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[0-6]\.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"ATS,
  MySQL,
  patch,
  Samba,
  Kernel,
  libxslt,
  OpenSSL,
  AirPort,
  ImageIO,
  OpenSSL,
  MobileMe,
  App Store,
  ColorSync,
  QuickLook,
  QuickTime,
  Libsystem,
  FTP Server,
  servermgrd,
  subversion,
  CoreGraphics,
  CoreFoundation,
  Certificate Trust Policy and
  International Components for Unicode.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2011-004");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.5.8 Update/Mac OS X Security Update 2011-004.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  if(version_is_less_equal(version:osVer, test_version:"10.5.8") ||
     version_in_range(version:osVer, test_version:"10.6", test_version2:"10.6.7"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.004"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
