###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_vuln01_apr14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Oracle Java SE Multiple Vulnerabilities-01 Apr 2014 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804544");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0453",
                "CVE-2014-0460", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2421",
                "CVE-2014-2427", "CVE-2014-2412", "CVE-2014-0457");
  script_bugtraq_id(66856, 66903, 66879, 66914, 66916, 66920, 66911, 66881, 66909,
                    66873, 66866);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-18 15:52:17 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle Java SE Multiple Vulnerabilities-01 Apr 2014 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Oracle Java
  SE and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities exists, For more
  details about the vulnerabilities refer the reference section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to manipulate certain data, cause a DoS (Denial of Service) and compromise a
  vulnerable system.");

  script_tag(name:"affected", value:"Oracle Java SE version 5.0u61, 6u71, 7u51
  and 8 on Windows");

  script_tag(name:"solution", value:"Upgrade to Java version 8u5 or 7u55 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57932");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57997");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(jreVer =~ "^(1\.(5|6|7|8))")
{
  if(version_is_equal(version:jreVer, test_version:"1.5.0.61")||
     version_is_equal(version:jreVer, test_version:"1.6.0.71")||
     version_is_equal(version:jreVer, test_version:"1.7.0.51")||
     version_is_equal(version:jreVer, test_version:"1.8.0"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Upgrade to 8u5 or 7u55");
    security_message(data:report);
    exit(0);
  }
}
