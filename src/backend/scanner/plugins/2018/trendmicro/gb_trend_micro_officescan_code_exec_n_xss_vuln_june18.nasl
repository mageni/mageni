###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro OfficeScan RCE And XSS Vulnerabilities June18
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:trend_micro:office_scan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813616");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2017-11393", "CVE-2017-11394");
  script_bugtraq_id(100127);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-27 11:07:13 +0530 (Wed, 27 Jun 2018)");
  script_name("Trend Micro OfficeScan RCE And XSS Vulnerabilities June18");

  script_tag(name:"summary", value:"This host is installed with Trend Micro
  OfficeScan and is prone to multiple code execution and cross site scripting
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper parsing of the tr and T parameters in Proxy.php, the process
    does not properly validate a user-supplied string before using it to execute
    a system call.

  - An input validation error in the third-party component previously used for
    mapping displays.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code on vulnerable installations of Trend Micro OfficeScan.");

  script_tag(name:"affected", value:"Trend Micro OfficeScan versions XG(12.0)
  prior to XG CP 1641 r1 and 11.0 SP1 prior to 11.0 SP1 CP 6392 r1.");

  script_tag(name:"solution", value:"Upgrade to OfficeScan XG CP 1708 or
  11.0 SP1 CP 6392 r1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  ## OSCE XG CP 1641-r1 has been removed from the Download Center because it was included in CP 1708
  ## Can result in FP, if CP 1641-r1 is already applied, not sure about build version after patch
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1117762-osce-11-0-sp1-critical-patch-6392-and-osce-xg-critical-patch-1641-is-now-available-in-the-download-c");
  script_xref(name:"URL", value:"http://esupport.trendmicro.com");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE )) exit(0);
trendVer = infos['version'];
path = infos['location'];

if(trendVer =~ "^(11|12)\.")
{
  ## http://docs.trendmicro.com/all/ent/officescan/v11.0/en-us/osce_11.0_sp1_server_readme.htm#7 - 11.0 SP1 =  11.0.2995
  ## http://files.trendmicro.com/products/officescan/11.0_SP1/osce_11_sp1_patch1_win_all_criticalpatch_6392_r1.html - 11.0 SP1 CP 6392 = 11.0.6392
  if(version_in_range(version:trendVer, test_version:"11.0.2995", test_version2:"11.0.6391" )){
    fix = "11.0 SP1 CP 6392 r1";
  }
  ## http://files.trendmicro.com/products/officescan/XG/SP1/osce_xg_sp1_win_en_criticalpatch_b4406.html - XG SP1 = 12.0.4345
  else if(version_in_range(version:trendVer, test_version:"12.0", test_version2:"12.0.1707" )){
    fix = "XG CP 1708";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:trendVer, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
