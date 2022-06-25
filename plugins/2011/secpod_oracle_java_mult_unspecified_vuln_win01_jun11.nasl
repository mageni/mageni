###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_mult_unspecified_vuln_win01_jun11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle Java SE Multiple Unspecified Vulnerabilities 01 - June11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902525");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0872", "CVE-2011-0786",
                "CVE-2011-0788", "CVE-2011-0817", "CVE-2011-0863");
  script_bugtraq_id(48140, 48141, 48146, 48133, 48135, 48134, 48138);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities 01 - June11 (Windows)");


  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"Oracle Java SE versions 6 Update 25 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - 2D

  - NIO

  - SAAJ

  - Deployment");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 6 Update 26 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to multiple
  unspecified vulnerabilities.");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html");
  script_xref(name:"URL", value:"http://java.com/en/download/index.jsp");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.25"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.25")) {
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
