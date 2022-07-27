###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_mult_unspecified_vuln_win_jun11.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Oracle Java SE Multiple Unspecified Vulnerabilities - June11 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902524");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867",
                "CVE-2011-0871", "CVE-2011-0873", "CVE-2011-0802", "CVE-2011-0814",
                "CVE-2011-0815", "CVE-2011-0862");
  script_bugtraq_id(48139, 48147, 48136, 48144, 48142, 48148, 48149, 48145,
                    48143, 48137);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities - June11 (Windows)");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"Oracle Java SE versions 6 Update 25 and prior, 5.0 Update 29 and prior,
  and 1.4.2_31 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - 2D

  - AWT

  - Sound

  - Swing

  - HotSpot

  - Networking

  - Deserialization

  - Java Runtime Environment");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 6 Update 26, 5.0 Update 30, 1.4.2_32
  or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to multiple
  unspecified vulnerabilities.");
  script_xref(name:"URL", value:"http://java.com/en/download/index.jsp");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  ## and 1.4.2_31 and prior
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.31") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.25") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.29"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  ## and 1.4.2_31 and prior
  if(version_is_less_equal(version:jdkVer, test_version:"1.4.2.31") ||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.25") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.29")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
