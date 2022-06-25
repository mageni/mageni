###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_upd_10_5_7_secupd_2009-002.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X 10.5.7 Update / Mac OS X Security Update 2009-002
#
# LSS-NVT-2010-024
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
  script_oid("1.3.6.1.4.1.25623.1.0.102035");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2008-2939", "CVE-2008-0456", "CVE-2009-0154", "CVE-2009-0025", "CVE-2009-0144",
               "CVE-2009-0157", "CVE-2009-0145", "CVE-2009-0155", "CVE-2009-0146", "CVE-2009-0147",
               "CVE-2009-0165", "CVE-2009-0148", "CVE-2009-0164", "CVE-2009-0150", "CVE-2009-0149",
               "CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186", "CVE-2008-3863", "CVE-2009-0519",
               "CVE-2009-0520", "CVE-2009-0114", "CVE-2009-0942", "CVE-2009-0943", "CVE-2009-0152",
               "CVE-2009-0153", "CVE-2008-3651", "CVE-2008-3652", "CVE-2009-0845", "CVE-2009-0846",
               "CVE-2009-0847", "CVE-2009-0844", "CVE-2008-1517", "CVE-2009-0156", "CVE-2008-3529",
               "CVE-2008-4309", "CVE-2009-0021", "CVE-2009-0159", "CVE-2008-3530", "CVE-2008-5077",
               "CVE-2008-3659", "CVE-2008-2829", "CVE-2008-3660", "CVE-2008-2666", "CVE-2008-2371",
               "CVE-2008-2665", "CVE-2008-3658", "CVE-2008-5557", "CVE-2009-0010", "CVE-2008-3443",
               "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2009-0161",
               "CVE-2009-0162", "CVE-2009-0944", "CVE-2009-0158", "CVE-2009-1717", "CVE-2009-0945",
               "CVE-2006-0747", "CVE-2007-2754", "CVE-2008-2383", "CVE-2008-1382", "CVE-2009-0040",
               "CVE-2009-0946");
  script_name("Mac OS X 10.5.7 Update / Mac OS X Security Update 2009-002");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3549");

  script_tag(name:"summary", value:"The remote host is missing Mac OS X 10.5.7 Update / Mac OS X Security Update 2009-002.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  Apache

 ATS

 BIND

 CFNetwork

 CoreGraphics

 Cscope

 CUPS

 Disk Images

 enscript

 Flash Player plug-in

 Help Viewer

 iChat

 International Components for Unicode

 IPSec

 Kerberos

 Kernel

 Launch Services

 libxml

 Net-SNMP

 Network Time

 Networking

 OpenSSL

 PHP

 QuickDraw Manager

 ruby

 Safari

 Spotlight

 system_cmds

 telnet

 Terminal

 WebKit

 X11");

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

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.6","Mac OS X Server 10.5.6","Mac OS X Server 10.5.6");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.002"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.002"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.6")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.7")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.6")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.7")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
