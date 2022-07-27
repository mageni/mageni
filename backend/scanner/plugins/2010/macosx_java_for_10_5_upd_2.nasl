###################################################################
# OpenVAS Vulnerability Test
# $Id: macosx_java_for_10_5_upd_2.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Java for Mac OS X 10.5 Update 2
#
# LSS-NVT-2010-029
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
  script_oid("1.3.6.1.4.1.25623.1.0.102040");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-05-28 13:49:16 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2008-3638", "CVE-2008-3637", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187",
               "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192",
               "CVE-2008-1195", "CVE-2008-1196", "CVE-2008-3104", "CVE-2008-3107", "CVE-2008-3108",
               "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-1193",
               "CVE-2008-1194", "CVE-2008-3103", "CVE-2008-3115", "CVE-2008-3105", "CVE-2008-3106",
               "CVE-2008-3109", "CVE-2008-3110");
  script_name("Java for Mac OS X 10.5 Update 2");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.5\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3179");

  script_tag(name:"summary", value:"The remote host is missing Java for Mac OS X 10.5 Update 2.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  Java");

  script_tag(name:"solution", value:"Update your Java for Mac OS X. Please see the references for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver || ssh_osx_ver !~ "^10\.5\.") exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.5.4","Mac OS X Server 10.5.4");

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.4")) {
  if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.5Update", diff:"2")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.4")) {
  if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.5Update", diff:"2")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
