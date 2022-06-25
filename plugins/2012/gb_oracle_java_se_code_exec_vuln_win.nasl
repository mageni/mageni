###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_code_exec_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Oracle Java SE Java Runtime Environment Code Execution Vulnerability - (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802947");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0507");
  script_bugtraq_id(52161);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-22 15:52:21 +0530 (Wed, 22 Aug 2012)");
  script_name("Oracle Java SE Java Runtime Environment Code Execution Vulnerability - (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48589");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");
  script_xref(name:"URL", value:"http://www.metasploit.com/modules/exploit/multi/browser/java_atomicreferencearray");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to bypass the Java sandbox
  restriction and execute arbitrary code.");
  script_tag(name:"affected", value:"Oracle Java SE versions 7 Update 2 and earlier, 6 Update 30 and earlier,
  and 5.0 Update 33 and earlier");
  script_tag(name:"insight", value:"The 'AtomicReferenceArray' class implementation does not ensure that the
  array is of the Object[] type, which allows attackers to cause a denial of
  service (JVM crash) or bypass Java sandbox restrictions.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to code
  execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  ## 5.0 Update 31 and earlier
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.2") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.30") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.33")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
