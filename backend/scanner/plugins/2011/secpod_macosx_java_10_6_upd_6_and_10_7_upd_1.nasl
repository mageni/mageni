###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_java_10_6_upd_6_and_10_7_upd_1.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Java for Mac OS X 10.6 Update 6 And 10.7 Update 1
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902630");
  script_tag(name:"creation_date", value:"2011-11-17 11:36:14 +0100 (Thu, 17 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_version("$Revision: 14307 $");
  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545",
                "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549",
                "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554",
                "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560",
                "CVE-2011-3561");
  script_bugtraq_id(49388, 50215, 50218, 50220, 50239, 50243, 50211, 50223, 50224,
                    50248, 50246, 50216, 50231, 50234, 50242, 50236, 50250);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Java for Mac OS X 10.6 Update 6 And 10.7 Update 1");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5045");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4884");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4885");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/Security-announce//2011/Nov/msg00000.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(6\.8|7\.2)");
  script_tag(name:"impact", value:"Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.");
  script_tag(name:"affected", value:"Java for Mac OS X v10.6.6 and v10.7.2 or Mac OS X Server v10.6.8 and v10.7.2.");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the below links.");
  script_tag(name:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 6 and 10.7 Update 1.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 6 and 10.7 Update 1.");

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
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6", diff:"6"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if(version_is_equal(version:osVer, test_version:"10.7.2"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.7", diff:"1")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
