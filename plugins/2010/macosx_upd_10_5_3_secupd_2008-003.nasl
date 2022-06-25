###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_upd_10_5_3_secupd_2008-003.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X 10.5.3 Update / Mac OS X Security Update 2008-003
#
# LSS-NVT-2010-020
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102031");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2008-1027", "CVE-2005-3352", "CVE-2005-3357", "CVE-2006-3747", "CVE-2007-1863",
               "CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-1028",
               "CVE-2008-1577", "CVE-2008-1575", "CVE-2008-1580", "CVE-2008-1030", "CVE-2008-1031",
               "CVE-2008-1032", "CVE-2008-1033", "CVE-2007-5275", "CVE-2007-6243", "CVE-2007-6637",
               "CVE-2007-6019", "CVE-2007-0071", "CVE-2008-1655", "CVE-2008-1654", "CVE-2008-1034",
               "CVE-2008-1035", "CVE-2008-1036", "CVE-2008-1571", "CVE-2008-1572", "CVE-2008-1573",
               "CVE-2007-5266", "CVE-2007-5268", "CVE-2007-5269", "CVE-2008-1574", "CVE-2008-0177",
               "CVE-2007-6359", "CVE-2008-1576", "CVE-2007-6612", "CVE-2008-1578", "CVE-2008-1579");
  script_name("Mac OS X 10.5.3 Update / Mac OS X Security Update 2008-003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1897");

  script_tag(name:"summary", value:"The remote host is missing Mac OS X 10.5.3 Update / Mac OS X Security Update 2008-003.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  AFP Server

 Apache

 AppKit

 Apple Pixlet Video

 ATS

 CFNetwork

 CoreFoundation

 CoreGraphics

 CoreTypes

 CUPS

 Flash Player Plug-in

 Help Viewer

 iCal

 International Components for Unicode

 Image Capture

 Image Capture

 ImageIO

 Kernel

 LoginWindow

 Mail

 ruby

 Single Sign-On

 Wiki Server");

  script_tag(name:"solution", value:"Update your Mac OS X operating system. Please see the references for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver || ssh_osx_ver !~ "^10\.[45]\.") exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.2","Mac OS X Server 10.5.2");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.003"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.003"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.3")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.3")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
