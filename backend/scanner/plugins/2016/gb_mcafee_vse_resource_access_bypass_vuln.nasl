##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_resource_access_bypass_vuln.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# McAfee VirusScan Enterprise Resource Access Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:mcafee:virusscan_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809974");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-3984");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 14:30:14 +0530 (Tue, 10 May 2016)");
  script_name("McAfee VirusScan Enterprise Resource Access Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee VirusScan
  Enterprise and is prone to resource access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the McAfee VirusScan
  Console (mcconsol.exe) does not properly check the password.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  Windows administrator to bypass the security restrictions and disable the
  antivirus engine without knowing the correct management password.");

  script_tag(name:"affected", value:"McAfee VirusScan Enterprise versions before
  8.8 Patch 7.");

  script_tag(name:"solution", value:"Upgrade to McAfee VirusScan Enterprise
  version 8.8 Patch 7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10151");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mcafVer = get_app_version(cpe:CPE)){
  exit(0);
}

## https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26382/en_US/vse_887_rn_0-00_en-us.pdf

if(version_is_less(version:mcafVer, test_version:"8.8.0.1528"))
{
  report = report_fixed_ver(installed_version:mcafVer, fixed_version:"8.8 patch 7(8.8.0.1528)");
  security_message(data:report);
  exit(0);
}

