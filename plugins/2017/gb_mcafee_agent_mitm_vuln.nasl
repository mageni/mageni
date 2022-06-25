###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_agent_mitm_vuln.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# McAfee Agent (MA) Man-in-the-Middle Attack Vulnerability
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

CPE = "cpe:/a:mcafee:mcafee_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810836");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2015-8987");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 16:26:54 +0530 (Mon, 10 Apr 2017)");
  script_name("McAfee Agent (MA) Man-in-the-Middle Attack Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee Agent
  and is prone to mitm attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when McAfee Agents migrate
  from one ePO server to another.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to make a McAfee Agent talk with another, possibly rogue, ePO server via McAfee
  Agent migration to another ePO server.");

  script_tag(name:"affected", value:"McAfee Agent version prior to 4.8.0 patch 3");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent 4.8.0 patch 3.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10101");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

## 4.8.0 patch 3 ==> 4.8.0.1938
##https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/25000/PD25667/en_US/McAfee_Agent_4_8_0_Patch3_RN.pdf
if(version_is_less(version:agentVer, test_version:"4.8.0.1938"))
{
  report = report_fixed_ver(installed_version:agentVer, fixed_version:"4.8.0 Patch 3");
  security_message(data:report);
  exit(0);
}
