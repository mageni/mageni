###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_arbitrary_code_exec_vuln_sep16.nasl 12359 2018-11-15 08:13:22Z cfischer $
#
# McAfee ePolicy Orchestrator Arbitrary Code Execution Vulnerability Sep16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809026");
  script_version("$Revision: 12359 $");
  script_cve_id("CVE-2015-8765");
  script_bugtraq_id(85696);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 09:13:22 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-01 10:20:57 +0530 (Thu, 01 Sep 2016)");
  script_name("McAfee ePolicy Orchestrator Arbitrary Code Execution Vulnerability Sep16");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/576313");
  script_xref(name:"URL", value:"http://www.mcafee.com/uk/products/epolicy-orchestrator.aspx");

  script_tag(name:"summary", value:"This host is installed with McAfee ePolicy
  Orchestrator and is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insecure deserialization of data
  in apache commons collections.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version 4.6.x through
  4.6.9, 5.0.x, 5.1.x before 5.1.3 Hotfix 1106041 and 5.3.x before 5.3.1 Hotfix 1106041");

  script_tag(name:"solution", value:"Apply the hotfix 5.1.3 Hotfix 1106041 and
  5.3.1 Hotfix 1106041 as mentioned in the reference link.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mcaPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mcaVer = get_app_version(cpe:CPE, port:mcaPort)){
  exit(0);
}

if(version_in_range(version:mcaVer, test_version:"4.6.0", test_version2:"4.6.9") ||
   version_in_range(version:mcaVer, test_version:"5.0.0", test_version2:"5.1.3") ||
   version_in_range(version:mcaVer, test_version:"5.3.0", test_version2:"5.3.1")){
  report = report_fixed_ver(installed_version:mcaVer, fixed_version:"Apply the appropriate Hotfix");
  security_message(data:report, port:mcaPort);
}
  exit(0);