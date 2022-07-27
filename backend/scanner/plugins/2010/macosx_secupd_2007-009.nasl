###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_secupd_2007-009.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X Security Update 2007-009
#
# LSS-NVT-2010-012
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
  script_oid("1.3.6.1.4.1.25623.1.0.102023");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2007-4708", "CVE-2007-4709", "CVE-2007-4710", "CVE-2007-5847", "CVE-2007-5848",
               "CVE-2007-4351", "CVE-2007-5849", "CVE-2007-5850", "CVE-2007-5476", "CVE-2007-4131",
               "CVE-2007-5851", "CVE-2007-5853", "CVE-2007-5854", "CVE-2007-6165", "CVE-2007-5855",
               "CVE-2007-5116", "CVE-2007-4965", "CVE-2007-5856", "CVE-2007-5857", "CVE-2007-5770",
               "CVE-2007-5379", "CVE-2007-5380", "CVE-2007-6077", "CVE-2007-5858", "CVE-2007-5859",
               "CVE-2007-4572", "CVE-2007-5398", "CVE-2006-0024", "CVE-2007-3876", "CVE-2007-5863",
               "CVE-2007-5860", "CVE-2007-5861", "CVE-2007-1218", "CVE-2007-3798", "CVE-2007-1659",
               "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767",
               "CVE-2007-4768");
  script_name("Mac OS X Security Update 2007-009");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT2012");

  script_tag(name:"summary", value:"The remote host is missing Security Update 2007-009.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  Address Book

 CFNetwork

 ColorSync

 Core Foundation

 CUPS

 Desktop Services

 Flash Player Plug-in

 GNU Tar

 iChat

 IO Storage Family

 Launch Services

 Mail

 perl

 python

 Quick Look

 ruby

 Safari

 Safari RSS

 Samba

 Shockwave Plug-in

 SMB

 Software Update

 Spin Tracer

 Spotlight

 tcpdump

 XQuery");

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

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.1","Mac OS X Server 10.5.1");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.1")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.1"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.1")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.1")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.1"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.1")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
