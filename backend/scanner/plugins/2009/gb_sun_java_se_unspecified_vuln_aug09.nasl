###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_se_unspecified_vuln_aug09.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Sun Java SE Unspecified Vulnerability In JDK/JRE/SDK - Aug09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800869");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2676");
  script_bugtraq_id(35946);
  script_name("Sun Java SE Unspecified Vulnerability In JDK/JRE/SDK - Aug09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36159");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263490-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-125136-16-1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl", "gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win_or_Linux/installed");

  script_tag(name:"impact", value:"An attacker may leverage this issue by modifying or creating of files on
  the affected application.");

  script_tag(name:"affected", value:"Sun Java JDK/JRE version 6 before Update 15 or 5.0 before Update 20
  Sun Java SDK/JRE version prior to 1.4.2_22.");

  script_tag(name:"insight", value:"An unspecified vulnerability exists in 'JNLPAppletlauncher' class, which can
  be exploited via vectors involving an untrusted Java applet.");

  script_tag(name:"summary", value:"This host is installed with Sun Java JDK/JRE/SDK and is prone to
  an unspecified vulnerability.");

  script_tag(name:"solution", value:"Upgrade to JDK/JRE version 6 Update 15 or 5 Update 20

  or

  Upgrade to SDK/JRE version 1.4.2_22.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");

if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.19")||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.14"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(isnull(jreVer))
{
  jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");

  if(isnull(jreVer))
    exit(0);
}

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.4", test_version2:"1.4.2.21")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.19")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.14")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
