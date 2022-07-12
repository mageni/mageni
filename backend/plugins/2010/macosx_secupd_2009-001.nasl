###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_secupd_2009-001.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X Security Update 2009-001
#
# LSS-NVT-2010-015
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
  script_oid("1.3.6.1.4.1.25623.1.0.102026");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2009-0142", "CVE-2009-0009", "CVE-2009-0020", "CVE-2009-0011", "CVE-2008-5050",
               "CVE-2008-5314", "CVE-2009-0012", "CVE-2008-5183", "CVE-2009-0013", "CVE-2007-4565",
               "CVE-2008-2711", "CVE-2009-0014", "CVE-2009-0015", "CVE-2008-1927", "CVE-2009-0017",
               "CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-2316",
               "CVE-2008-3142", "CVE-2008-3144", "CVE-2008-4864", "CVE-2007-4965", "CVE-2008-5031",
               "CVE-2009-0018", "CVE-2009-0019", "CVE-2009-0137", "CVE-2009-0138", "CVE-2009-0139",
               "CVE-2009-0140", "CVE-2008-2379", "CVE-2008-3663", "CVE-2008-1377", "CVE-2008-1379",
               "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362", "CVE-2006-1861", "CVE-2006-3467",
               "CVE-2007-1351", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2007-1352",
               "CVE-2007-1667", "CVE-2009-0141");
  script_name("Mac OS X Security Update 2009-001");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3438");

  script_tag(name:"summary", value:"The remote host is missing Security Update 2009-001.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  AFP Server

 Apple Pixlet Video

 CarbonCore

 CFNetwork

 Certificate Assistant

 ClamAV

 CoreText

 CUPS

 DS Tools

 fetchmail

 Folder Manager

 FSEvents

 Network Time

 perl

 Printing

 python

 Remote Apple Events

 Safari RSS

 servermgrd

 SMB

 SquirrelMail

 X11

 XTerm");

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

pkg_for_ver = make_list("Mac OS X 10.5.6","Mac OS X Server 10.5.6","Mac OS X 10.4.11","Mac OS X Server 10.4.11");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.6")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.6"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.6")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.6")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.6"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.6")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.001"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
