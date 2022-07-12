###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_agent_log_viewer_dos_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# McAfee Agent (MA) 'log viewer' Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810602");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-3896");
  script_bugtraq_id(95903);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-16 12:13:05 +0530 (Thu, 16 Feb 2017)");
  script_name("McAfee Agent (MA) 'log viewer' Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is installed with McAfee Agent
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the remote
  log viewing functionality, where an input parameter passed through the URL is
  not completely validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"McAfee Agent (MA) version 5.0.x before
  5.0.4 Hotfix 1174804 (5.0.4.449)");

  script_tag(name:"solution", value:"Upgrade to McAfee Agent (MA) 5.0.4 hotfix
  1174804 (5.0.4.449) or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  ## This issue is encountered only if both of the following two conditions are met (not enabled by default):
  ## McAfee Agent remote log viewing functionality is enabled.
  ## Remote logs access is not restricted to ePolicy Orchestrator administrators only.
  script_tag(name:"qod", value:"30");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10183");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_mcafee_agent_detect.nasl");
  script_mandatory_keys("McAfee/Agent/Win/Ver");
  script_xref(name:"URL", value:"http://www.mcafee.com/us");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!agentVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(agentVer =~ "^5\.0\.")
{
  if(version_is_less(version:agentVer, test_version:"5.0.4.449"))
  {
    report = report_fixed_ver(installed_version:agentVer, fixed_version:"5.0.4 Hotfix 1174804 (5.0.4.449)");
    security_message(data:report);
    exit(0);
  }
}
