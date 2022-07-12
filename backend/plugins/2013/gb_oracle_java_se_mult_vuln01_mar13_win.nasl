###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln01_mar13_win.nasl 12047 2018-10-24 07:38:41Z cfischer $
#
# Oracle Java SE Multiple Vulnerabilities -01 March 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803327");
  script_version("$Revision: 12047 $");
  script_cve_id("CVE-2013-1493", "CVE-2013-0809");
  script_bugtraq_id(58296, 58238);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-07 18:02:25 +0530 (Thu, 07 Mar 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -01 March 13 (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028237");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438422.php");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438437.php");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alert-cve-2013-1493-1915081.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code,
  corrupt memory or cause a denial of service.");
  script_tag(name:"affected", value:"Oracle Java SE Versions 7 Update 15 and earlier, 6 Update 41 and earlier,
  5 Update 40 and earlier on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Unspecified error in 2D component.

  - Error in color management(CMM) functionality in the 2D component via image
    with crafted raster parameter.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer && jreVer=~ "^(1.5|1.6|1.7)")
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.15")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.41")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.40"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
