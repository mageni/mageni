###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_macosx_su11-005.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Mac OS X Certificate Trust Policy Information Disclosure Vulnerability (2011-005)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802798");
  script_version("$Revision: 14307 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-26 18:25:17 +0530 (Tue, 26 Jun 2012)");
  script_name("Mac OS X Certificate Trust Policy Information Disclosure Vulnerability (2011-005)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4920");
  script_xref(name:"URL", value:"http://support.apple.com/kb/DL1446");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Sep/msg00000.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain sensitive information.");
  script_tag(name:"affected", value:"Certificate Trust Policy");
  script_tag(name:"insight", value:"The fraudulent certificates were issued by multiple certificate authorities
  operated by DigiNotar.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2011-005.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2011-005.");
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
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.005")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
