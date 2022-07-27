###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_imc_mult_rce_vul.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# HP Intelligent Management Center (iMC) Multiple RCE Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:intelligent_management_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811626");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-12487", "CVE-2017-12488", "CVE-2017-12489", "CVE-2017-12490",
		"CVE-2017-12491", "CVE-2017-12492", "CVE-2017-12493", "CVE-2017-12494",
		"CVE-2017-12495", "CVE-2017-12496", "CVE-2017-12497", "CVE-2017-12498",
		"CVE-2017-12499", "CVE-2017-12500", "CVE-2017-12501", "CVE-2017-12502",
		"CVE-2017-12503", "CVE-2017-12504", "CVE-2017-12505", "CVE-2017-12506",
		"CVE-2017-12507", "CVE-2017-12508", "CVE-2017-12509", "CVE-2017-12510",
		"CVE-2017-12511", "CVE-2017-12512", "CVE-2017-12513", "CVE-2017-12514",
		"CVE-2017-12515", "CVE-2017-12516", "CVE-2017-12517", "CVE-2017-12518",
		"CVE-2017-12519", "CVE-2017-12520", "CVE-2017-12521", "CVE-2017-12522",
		"CVE-2017-12523", "CVE-2017-12524", "CVE-2017-12525", "CVE-2017-12526",
		"CVE-2017-12527", "CVE-2017-12528", "CVE-2017-12529", "CVE-2017-12530",
		"CVE-2017-12531", "CVE-2017-12532", "CVE-2017-12533", "CVE-2017-12534",
		"CVE-2017-12535", "CVE-2017-12536", "CVE-2017-12537", "CVE-2017-12538",
		"CVE-2017-12539", "CVE-2017-12540", "CVE-2017-12541");
  script_bugtraq_id(100367);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-17 15:32:25 +0530 (Thu, 17 Aug 2017)");
  script_name("HP Intelligent Management Center (iMC) Multiple RCE Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with HP Intelligent
  Management Center (iMC) and is prone to multiple RCE vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"HP Intelligent Management Center (iMC)
  version 7.3 E0504");

  script_tag(name:"solution", value:"Upgrade to HP Intelligent Management Center
  (iMC) version 7.3 E0506 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03768en_us");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hp_imc_detect.nasl");
  script_mandatory_keys("HPE/iMC/Win/Ver");
  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:hpVer, test_version:"7.3.E0504"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"7.3.E0506");
  security_message(data:report);
  exit(0);
}
