###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su11-006.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X v10.6.8 Multiple Vulnerabilities (2011-006)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802336");
  script_version("$Revision: 14307 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2011-0419", "CVE-2011-3192", "CVE-2011-0185", "CVE-2011-3437",
                "CVE-2011-0229", "CVE-2011-0230", "CVE-2011-1910", "CVE-2011-2464",
                "CVE-2009-4022", "CVE-2010-0097", "CVE-2010-3613", "CVE-2010-3614",
                "CVE-2011-0231", "CVE-2011-3246", "CVE-2011-0259", "CVE-2011-0187",
                "CVE-2011-0224", "CVE-2011-0260", "CVE-2011-3212", "CVE-2011-3213",
                "CVE-2011-3214", "CVE-2011-1755", "CVE-2011-3215", "CVE-2011-3216",
                "CVE-2011-3227", "CVE-2011-0707", "CVE-2011-3217", "CVE-2011-3435",
                "CVE-2010-3436", "CVE-2010-4645", "CVE-2011-0420", "CVE-2011-0421",
                "CVE-2011-0708", "CVE-2011-1092", "CVE-2011-1153", "CVE-2011-1466",
                "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470",
                "CVE-2011-1471", "CVE-2011-0411", "CVE-2010-1634", "CVE-2010-2089",
                "CVE-2011-1521", "CVE-2011-3228", "CVE-2011-0249", "CVE-2011-0250",
                "CVE-2011-0251", "CVE-2011-0252", "CVE-2011-3218", "CVE-2011-3219",
                "CVE-2011-3220", "CVE-2011-3221", "CVE-2011-3222", "CVE-2011-3223",
                "CVE-2011-3225", "CVE-2010-1157", "CVE-2010-2227", "CVE-2010-3718",
                "CVE-2010-4172", "CVE-2011-0013", "CVE-2011-0534", "CVE-2011-3224",
                "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692", "CVE-2011-3436",
                "CVE-2011-3226", "CVE-2011-0226");
  script_bugtraq_id(47820, 49303, 50092, 50112, 50091, 50099, 48007, 48566, 37118,
                    37865, 45133, 45137, 50098, 50115, 50067, 46992, 50095, 50120,
                    50109, 50116, 50111, 48250, 50113, 50121, 50129, 46464, 50117,
                    50114, 50146, 50153, 48619, 48660, 48618, 44723, 45668, 46429,
                    46354, 46365, 46786, 46854, 46967, 46968, 46977, 46970, 46969,
                    46975, 46767, 40370, 40863, 47024, 50127, 48993, 49038, 50122,
                    50068, 50130, 50131, 50100, 50101, 50144, 39635, 41544, 46177,
                    45015, 46174, 46164, 50150);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X v10.6.8 Multiple Vulnerabilities (2011-006)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5000");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5002");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Oct//msg00003.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial of service condition.");
  script_tag(name:"affected", value:"Apache, Application Firewall, ATS, BIND, Certificate Trust Policy, CFNetwork,
  CoreFoundation, CoreMedia, CoreProcesses, CoreStorage, File Systems,
  iChat Server, IOGraphics, Kernel, libsecurity, Mailman, MediaKit,
  Open Directory, PHP, postfix, python, QuickTime, SMB File Server, Tomcat,
  User Documentation, Web Server and X11.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2011-006");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2011-006.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

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
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.006"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
