###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_manageengine_servicedesk_plus_mult_xss_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# ManageEngine ServiceDesk Plus Multiple Stored XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902469");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ManageEngine ServiceDesk Plus Multiple Stored XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/service-desk/readme-8.0.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104365/ZSL-2011-5039.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");
  script_require_ports("Services/www", 8080);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks.");
  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to an error in,

  - 'WorkOrder.do', 'Problems.cc', 'AddNewProblem.cc', 'ChangeDetails.c' when
    processing the 'reqName' parameter.

  - 'WorkOrder.do' when processing the various parameters.

  - 'AddSolution.do' when handling add action via ' keywords' and 'comment'
    parameters.

  - 'ContractDef.do' when processing the 'supportDetails', 'contractName'
    and 'comments' parameters.

  - 'VendorDef.do' and 'MarkUnavailability.jsp' hen processing the
    'organizationName' and 'COMMENTS' parameters.

  - 'HomePage.do', 'MySchedule.do', and 'WorkOrder.d' when handling the HTTP
     header elements 'referer' and 'accept-language'.");
  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus 8.0 Build 8015 or later");
  script_tag(name:"summary", value:"This host is running ManageEngine ServiceDesk Plus and is prone to
  multiple stored cross site scripting vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:manageengine:servicedesk_plus';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(' Build ' >< vers){
  vers = ereg_replace(pattern:" Build ", string:vers, replace:".");
}

if(version_is_less_equal(version:vers, test_version:"8.0.0.8014")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.0.0.8015");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
