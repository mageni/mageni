###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su12-004.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X v10.6.8 Multiple Vulnerabilities (2012-004)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802968");
  script_version("$Revision: 14307 $");
  script_cve_id("CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0650",
                "CVE-2012-1173", "CVE-2012-3719", "CVE-2012-0831", "CVE-2012-1172",
                "CVE-2012-1823", "CVE-2012-2143", "CVE-2012-2311", "CVE-2012-2386",
                "CVE-2012-2688", "CVE-2012-0671", "CVE-2012-0670", "CVE-2012-3722",
                "CVE-2012-0668", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317",
                "CVE-2011-3026", "CVE-2011-3048", "CVE-2011-4599", "CVE-2011-3048",
                "CVE-2011-3389");
  script_bugtraq_id(51705, 51407, 51706, 55623, 52891, 55623, 51954, 53403, 49778,
                    53388, 53729, 47545, 54638, 53584, 53582, 55612, 49957, 50494,
                    50802, 52049, 52830, 51006, 52830);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-25 19:33:16 +0530 (Tue, 25 Sep 2012)");
  script_name("Mac OS X v10.6.8 Multiple Vulnerabilities (2012-004)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5501");
  script_xref(name:"URL", value:"http://support.apple.com/kb/DL1586");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50628/");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a buffer overflow,
  disclose potentially sensitive information or cause a DoS.");
  script_tag(name:"affected", value:"Apache
  BIND
  CoreText
  Data Security
  DirectoryService
  ImageIO
  Installer
  International Components for Unicode
  Kernel
  LoginWindow
  Mail
  Mobile Accounts
  PHP
  Profile Manager
  QuickLook
  QuickTime
  Ruby
  USB");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2012-004.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2012-004.");
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
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.004")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
