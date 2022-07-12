###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_upd_10_6_3_secupd_2010-002.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X 10.6.3 Update / Mac OS X Security Update 2010-002
#
# LSS-NVT-2010-028
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
  script_oid("1.3.6.1.4.1.25623.1.0.102039");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2010-0056", "CVE-2009-2801", "CVE-2010-0057", "CVE-2010-0533", "CVE-2009-3095",
               "CVE-2010-0058", "CVE-2010-0059", "CVE-2010-0060", "CVE-2010-0062", "CVE-2010-0063",
               "CVE-2010-0393", "CVE-2009-2417", "CVE-2009-0037", "CVE-2009-2632", "CVE-2009-0688",
               "CVE-2010-0064", "CVE-2010-0537", "CVE-2010-0065", "CVE-2010-0497", "CVE-2010-0498",
               "CVE-2010-0535", "CVE-2010-0500", "CVE-2010-0524", "CVE-2010-0501", "CVE-2006-1329",
               "CVE-2010-0502", "CVE-2010-0503", "CVE-2010-0504", "CVE-2010-0505", "CVE-2010-0041",
               "CVE-2010-0042", "CVE-2010-0043", "CVE-2010-0506", "CVE-2010-0507", "CVE-2009-0689",
               "CVE-2010-0508", "CVE-2010-0525", "CVE-2008-0564", "CVE-2008-4456", "CVE-2008-7247",
               "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030", "CVE-2010-0509", "CVE-2010-0510",
               "CVE-2008-5302", "CVE-2008-5303", "CVE-2009-3557", "CVE-2009-3558", "CVE-2009-3559",
               "CVE-2009-4017", "CVE-2009-4142", "CVE-2009-4143", "CVE-2010-0511", "CVE-2010-0512",
               "CVE-2010-0513", "CVE-2010-0514", "CVE-2010-0515", "CVE-2010-0516", "CVE-2010-0517",
               "CVE-2010-0518", "CVE-2010-0519", "CVE-2010-0520", "CVE-2010-0526", "CVE-2009-2422",
               "CVE-2009-3009", "CVE-2009-4214", "CVE-2009-1904", "CVE-2010-0521", "CVE-2010-0522",
               "CVE-2009-2906", "CVE-2009-0580", "CVE-2009-0033", "CVE-2009-0783", "CVE-2008-5515",
               "CVE-2009-0781", "CVE-2009-2901", "CVE-2009-2902", "CVE-2009-2693", "CVE-2008-0888",
               "CVE-2008-2712", "CVE-2008-4101", "CVE-2009-0316", "CVE-2010-0523", "CVE-2010-0534",
               "CVE-2009-2042", "CVE-2003-0063", "CVE-2010-0055");
  script_name("Mac OS X 10.6.3 Update / Mac OS X Security Update 2010-002");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[56]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4077");

  script_tag(name:"summary", value:"The remote host is missing Mac OS X 10.6.3 Update / Mac OS X Security Update 2010-002.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  AppKit

 Application Firewall

 AFP Server

 Apache

 ClamAV

 CoreAudio

 CoreMedia

 CoreTypes

 CUPS

 curl

 Cyrus IMAP

 Cyrus SASL

 DesktopServices

 Disk Images

 Directory Services

 Dovecot

 Event Monitor

 FreeRADIUS

 FTP Server

 iChat Server

 ImageIO

 Image RAW

 Libsystem

 Mail

 Mailman

 MySQL

 OS Services

 Password Server

 perl

 PHP

 Podcast Producer

 Preferences

 PS Normalizer

 QuickTime

 Ruby

 Server Admin

 SMB

 Tomcat

 unzip

 vim

 Wiki Server

 X11

 xar");

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
if (!ssh_osx_ver || ssh_osx_ver !~ "^10\.[56]\.") exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.5.8","Mac OS X Server 10.5.8","Mac OS X 10.6.2","Mac OS X Server 10.6.2");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.8")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.8"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.8")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.002"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.8")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.8"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.8")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2010.002"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.6.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.6.3")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.6.2")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.6.3")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
