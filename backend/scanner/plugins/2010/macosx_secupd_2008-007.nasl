###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_secupd_2008-007.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X Security Update 2008-007
#
# LSS-NVT-2010-014
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
  script_oid("1.3.6.1.4.1.25623.1.0.102025");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2007-6420", "CVE-2008-1678", "CVE-2008-2364", "CVE-2008-1389", "CVE-2008-3912",
               "CVE-2008-3913", "CVE-2008-3914", "CVE-2008-3642", "CVE-2008-3641", "CVE-2008-3643",
               "CVE-2008-1767", "CVE-2007-2691", "CVE-2007-5969", "CVE-2008-0226", "CVE-2008-0227",
               "CVE-2008-2079", "CVE-2008-3645", "CVE-2007-4850", "CVE-2008-0674", "CVE-2008-2371",
               "CVE-2008-3646", "CVE-2008-3647", "CVE-2008-4211", "CVE-2008-4212", "CVE-2008-4214",
               "CVE-2007-6286", "CVE-2008-0002", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370",
               "CVE-2008-2938", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2008-2712",
               "CVE-2008-4101", "CVE-2008-3432", "CVE-2008-3294", "CVE-2008-4215");
  script_name("Mac OS X Security Update 2008-007");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3216");

  script_tag(name:"summary", value:"The remote host is missing Security Update 2008-007.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  Apache

 Certificates

 ClamAV

 ColorSync

 CUPS

 Finder

 launchd

 libxslt

 MySQL Server

 Networking

 PHP

 Postfix

 PSNormalizer

 QuickLook

 rlogin

 Script Editor

 Single Sign-On

 Tomcat

 vim

 Weblog");

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

pkg_for_ver = make_list("Mac OS X 10.5.5","Mac OS X Server 10.5.5","Mac OS X 10.4.11","Mac OS X Server 10.4.11");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.5")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.5"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.5")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.007"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.5")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.5"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.5")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.007"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.007"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.007"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
