###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java JDK/JRE Multiple Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800384");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096",
                "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100",
                "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104",
                "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");
  script_bugtraq_id(34240);
  script_name("Sun Java JDK/JRE Multiple Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34489");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0394.html");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254569-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2009-04/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to cause XSS, arbitrary code
  execution, various buffer overflows, bypass security restrictions and can
  cause denial of service attacks inside the context of the affected system.");
  script_tag(name:"affected", value:"Sun Java JRE 6 Update 12 and prior.

  Sun Java JRE 5.0 Update 17 and prior.

  Sun Java JRE 1.4.2_19 and prior.

  Sun Java JRE 1.3.1_24 and prior.");
  script_tag(name:"insight", value:"For more information about vulnerabilities on Sun Java go through reference.");
  script_tag(name:"solution", value:"Upgrade to JRE version 6 Update 13

  Upgrade to JRE version 5 Update 18

  Upgrade to JRE version 1.4.2_20

  Upgrade to JRE version 1.3.1_25.");
  script_tag(name:"summary", value:"This host is installed with Sun Java JDK/JRE and is prone to
  Multiple Vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(!jreVer)
  exit(0);

if(jreVer)
{
  # and 1.6 < 1.6.0_13 (6 Update 13)
  if(version_in_range(version:jreVer, test_version:"1.3", test_version2:"1.3.1.24") ||
     version_in_range(version:jreVer, test_version:"1.4", test_version2:"1.4.2.19") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.17") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.12")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
