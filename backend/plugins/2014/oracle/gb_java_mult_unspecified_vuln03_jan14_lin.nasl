###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln03_jan14_lin.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Oracle Java SE Multiple Unspecified Vulnerabilities-03 Jan 2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.108415");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5905", "CVE-2013-5906",
                "CVE-2013-5907", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376",
                "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422",
                "CVE-2014-0423", "CVE-2014-0428");
  script_bugtraq_id(64924, 64926, 64934, 64903, 64894, 64930, 64922, 64907,
                    64918, 64937, 64932, 64921, 64914, 64935);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-22 10:20:04 +0530 (Wed, 22 Jan 2014)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-03 Jan 2014 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exists, For more details about the
vulnerabilities refer the reference section.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to affect confidentiality,
integrity and availability via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java SE 7 update 45 and prior, Java SE 6 update 65 and prior, Java SE 5
update 55 and prior on Linux");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56485");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64930");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(jreVer =~ "^(1\.(6|7|5))")
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.45")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.65")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.55"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);