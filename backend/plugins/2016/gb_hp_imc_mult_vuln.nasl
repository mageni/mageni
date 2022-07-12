###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_imc_mult_vuln.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# HP Intelligent Management Center (iMC) Multiple Vulnerabilities
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809283");
  script_version("$Revision: 11811 $");
  script_cve_id("CVE-2012-5201", "CVE-2012-5202", "CVE-2012-5203", "CVE-2012-5204",
                "CVE-2012-5205", "CVE-2012-5206", "CVE-2012-5207", "CVE-2012-5208",
                "CVE-2012-5209", "CVE-2012-5210", "CVE-2012-5211", "CVE-2012-5212",
                "CVE-2012-5213");
  script_bugtraq_id(58673, 58675, 58672, 58676);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-22 18:02:02 +0530 (Thu, 22 Sep 2016)");
  script_name("HP Intelligent Management Center (iMC) Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with HP Intelligent
  Management Center (iMC) and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an unspecified
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to obtain sensitive information, modify data, or cause a denial
  of service or to execute arbitrary code.");

  script_tag(name:"affected", value:"HP Intelligent Management Center (iMC)
  prior to 5.2 E0401");

  script_tag(name:"solution", value:"Upgrade to HP Intelligent Management Center
  (iMC) version 5.2 E0401 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03689276");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hp_imc_detect.nasl");
  script_mandatory_keys("HPE/iMC/Win/Ver");
  script_xref(name:"URL", value:"https://www.hpe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(revcomp(a: hpVer, b: "5.2.E0401") < 0)
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"5.2 E0401");
  security_message(data:report);
  exit(0);
}
