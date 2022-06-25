###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_java_10_6_upd_10.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Java for Mac OS X 10.6 Update 10
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
  script_oid("1.3.6.1.4.1.25623.1.0.803029");
  script_version("$Revision: 14307 $");
  #Remark: NIST don't see "security-in-depth fixes" as software flaws so this CVSS has a value of 0.0.
  #However we still should report missing security fixes with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-21 11:04:53 +0530 (Fri, 21 Sep 2012)");
  script_name("Java for Mac OS X 10.6 Update 10");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-0547");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5473");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50133");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027458");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html");

  script_tag(name:"impact", value:"Has no impact and remote attack vectors. The missing patch is a security-in-depth fix released by Oracle.");
  script_tag(name:"affected", value:"Java for Mac OS X v10.6.8 or Mac OS X Server v10.6.8");
  script_tag(name:"insight", value:"Unspecified vulnerability in the JRE component related to AWT sub-component.");
  script_tag(name:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 10.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 10.");

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

if("Mac OS X" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6", diff:"10"))
    {
      security_message(port:0);
      exit(0);
    }
  }
}

exit(99);