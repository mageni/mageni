###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln01_oct13.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 Oct 2013 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804117");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5780",
                "CVE-2013-5842", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5825",
                "CVE-2013-5843", "CVE-2013-5850", "CVE-2013-5849", "CVE-2013-3829",
                "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5801", "CVE-2013-5802",
                "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5778",
                "CVE-2013-5774", "CVE-2013-5782", "CVE-2013-5783");
  script_bugtraq_id(63137, 63121, 63148, 63150, 63143, 63146, 63101, 63115,
                     63151, 63153, 63106, 63120, 63102, 63095, 63147, 63135,
                     63082, 63149, 63118, 63134, 63128, 63103, 63154);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-25 15:41:52 +0530 (Fri, 25 Oct 2013)");
  script_name("Oracle Java SE JRE Multiple Unspecified  Vulnerabilities-01 Oct 2013 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Oracle Java SE JRE and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exists, For more details about the
vulnerabilities refer the reference section.");
  script_tag(name:"affected", value:"Oracle Java SE 7 update 40 and earlier, 6 update 60 and earlier, 5 update 51
and earlier on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to affect confidentiality,
integrity, and availability via unknown vectors.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63129");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version (cpe:CPE)){
    exit(0);
  }
}


if(jreVer =~ "^(1\.(5|6|7))")
{
  if(version_in_range(version:jreVer, test_version:"1.5.0", test_version2:"1.5.0.51")||
     version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.60")||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.40"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
