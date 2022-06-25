###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln01_july15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 July 2015 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805722");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-4760", "CVE-2015-4749", "CVE-2015-4748", "CVE-2015-4733",
                "CVE-2015-4732", "CVE-2015-4731", "CVE-2015-2664", "CVE-2015-2638",
                "CVE-2015-2637", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627",
                "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2601", "CVE-2015-2590");
  script_bugtraq_id(75784, 75890, 75854, 75832, 75823, 75812, 75857, 75833, 75883,
                    75874, 75895, 75893, 75796, 75861, 75867, 75818);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-20 17:10:19 +0530 (Mon, 20 Jul 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 July 2015 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  JRE and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist due to unspecified
  flaws related to multiple unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"Oracle Java SE 6 update 95, 7 update 80,
  8 update 45 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(jreVer =~ "^(1\.(6|8|7))")
{
  if(version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.95")||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.80")||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.45"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch from the referenced advisory.");
    security_message(data:report);
    exit(0);
  }
}
