###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln_oct11_win_03.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Oracle Java SE Multiple Vulnerabilities - October 2011 (Windows03)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802275");
  script_version("$Revision: 12018 $");
  script_cve_id("CVE-2011-3545", "CVE-2011-3549");
  script_bugtraq_id(50220, 50223);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)");
  script_name("Oracle Java SE Multiple Vulnerabilities - October 2011 (Windows03)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46512");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java SE versions 6 Update 27 and earlier, 5.0 Update 31 and earlier,
  and 1.4.2_33 and earlier.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the following
  components:

  - Sound

  - Swing");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE versions 6 Update 29, 5.0 Update 32, 1.4.2_34
  or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to multiple
  vulnerabilities.");
  exit(0);
}


include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  ## 5.0 Update 31 and earlier, and 1.4.2_33 and earlier
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.33") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.27") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.31"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  ## 5.0 Update 31 and earlier, and 1.4.2_33 and earlier
  if(version_is_less_equal(version:jdkVer, test_version:"1.4.2.33") ||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.27") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.31")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
     exit(0);
  }
}

exit(99);
