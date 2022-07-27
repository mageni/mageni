###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_mult_vuln02_aug13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-02 August13
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803865");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4882", "CVE-2013-4883");
  script_bugtraq_id(61421, 61422);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-09 15:40:39 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-02 August13");

  script_tag(name:"summary", value:"This host is running McAfee ePolicy Orchestrator and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator version 4.5.7 or higher.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Multiple flaw are due to improper sanitation of user supplied input via,

  - 'instanceId' parameter upon submission to the /core/loadDisplayType.do
  script.

  - 'instanceId', 'orion.user.security.token', and 'ajaxMode' parameters upon
  submission to the /console/createDashboardContainer.do script.

  - 'uid' parameter upon submission to the /core/showRegisteredTypeDetails.do
  and /ComputerMgmt/sysDetPanelBoolPie.do scripts.

  - 'uid', 'orion.user.security.token', and 'ajaxMode' parameters upon submission
  to the /ComputerMgmt/sysDetPanelSummary.do and /ComputerMgmt/sysDetPanelQry.do
  scripts.");
  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator (ePO) version 4.6.6 and earlier");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
or script code in a user's browser session in the context of an affected
site and inject or manipulate SQL queries in the back-end database, allowing
for the manipulation or disclosure of arbitrary data.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54143");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26807");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB78824");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);
  script_xref(name:"URL", value:"http://www.mcafee.com/in/products/epolicy-orchestrator.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE);
if(!port){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(vers)
{
  if(version_is_less(version:vers, test_version:"4.6.7"))
  {
    security_message(port);
    exit(0);
  }
}
