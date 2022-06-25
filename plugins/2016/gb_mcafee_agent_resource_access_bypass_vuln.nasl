###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_agent_resource_access_bypass_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# McAfee Agent (MA) Resource Access Bypass Vulnerability
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

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807973");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-3984");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 13:07:15 +0530 (Tue, 10 May 2016)");
  script_name("McAfee Agent (MA) Resource Access Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee Agent
  and is prone to resource access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the McAfee VirusScan
  Console (mcconsol.exe) does not properly check the password.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  Windows administrator to bypass the security restrictions and disable the
  antivirus engine without knowing the correct management password.");

  script_tag(name:"affected", value:"McAfee Agent (MA) version 5.x before
  5.0.2 hotfix 1110392(5.0.2.333)");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 5.0.2 hotfix
  1110392 (5.0.2.333) or 5.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10151");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com/us/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(agentVer =~ "^5\.")
{
  ## https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26042/en_US/ma_502_rn_en-us.pdf
  if(version_is_less(version:agentVer, test_version:"5.0.2.333"))
  {
    report = report_fixed_ver(installed_version:agentVer, fixed_version:"5.0.2 hotfix 1110392 (5.0.2.333)");
    security_message(data:report);
    exit(0);
  }
}
