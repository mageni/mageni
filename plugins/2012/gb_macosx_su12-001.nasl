###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su12-001.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X Multiple Vulnerabilities (2012-001)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802392");
  script_version("$Revision: 14307 $");
  script_cve_id("CVE-2011-3444", "CVE-2011-3348", "CVE-2011-3389", "CVE-2011-3246",
                "CVE-2011-3447", "CVE-2011-0200", "CVE-2011-3252", "CVE-2011-3448",
                "CVE-2011-3449", "CVE-2011-3450", "CVE-2011-2192", "CVE-2011-2895",
                "CVE-2011-3452", "CVE-2011-3441", "CVE-2011-3453", "CVE-2011-3422",
                "CVE-2011-3457", "CVE-2011-1148", "CVE-2011-1657", "CVE-2011-1938",
                "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3189",
                "CVE-2011-3267", "CVE-2011-3268", "CVE-2011-3256", "CVE-2011-3328",
                "CVE-2011-3458", "CVE-2011-3248", "CVE-2011-3459", "CVE-2011-3250",
                "CVE-2011-3460", "CVE-2011-3249", "CVE-2010-1637", "CVE-2010-2813",
                "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-1752",
                "CVE-2011-1783", "CVE-2011-1921", "CVE-2011-3462", "CVE-2011-2204",
                "CVE-2011-3463", "CVE-2011-2937", "CVE-2011-0241", "CVE-2011-1167");
  script_bugtraq_id(51810, 49616, 49778, 50115, 51813, 48416, 50065, 51817, 51812,
                    51815, 48434, 49124, 48833, 46951, 49744, 51819, 50641, 51807,
                    49429, 51808, 46843, 49252, 47950, 48259, 49241, 49249, 49376,
                    50155, 51809, 50400, 51811, 50401, 51814, 50404, 40291, 42399,
                    48648, 48091, 51818, 48456, 51816, 49229, 47820, 49303, 50092,
                    50112, 50091, 50099, 48007, 48566, 37118);
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-06 17:42:28 +0530 (Mon, 06 Feb 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X Multiple Vulnerabilities (2012-001)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5130");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47843/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026627");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Feb/msg00001.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[67]\.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"Address Book, Apache, CFNetwork, ColorSync, CoreAudio, CoreText, CoreUI
  curl, Data Security, dovecot, filecmds, ImageIO, Internet Sharing, Libinfo,
  libresolv, libsecurity, OpenGL, PHP, QuickTime, SquirrelMail, X11, Webmail,
  Tomcat, WebDAV Sharing.");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the reference section.");
  script_tag(name:"solution", value:"Upgrade to Mac OS X 10.7.3 or
  Run Mac Updates and update the Security Update 2012-001");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X Update/Mac OS X Security Update 2012-001.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");

  exit(0);
}

include("version_func.inc");
include("pkg-lib-macosx.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.001"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if(version_in_range(version:osVer, test_version:"10.7", test_version2:"10.7.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
