###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_xss_vuln_jun15.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# McAfee ePolicy Orchestrator Cross Site Scripting Vulnerability - June15
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805594");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2015-4559");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-24 11:25:11 +0530 (Wed, 24 Jun 2015)");
  script_name("McAfee ePolicy Orchestrator Cross Site Scripting Vulnerability - June15");

  script_tag(name:"summary", value:"This host is installed with McAfee ePolicy
  Orchestrator and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the product
  deployment feature in the Java core web services.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary HTML and script code in the context of an
  affected site.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version 5.x
  before 5.1.2");

  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator
  version 5.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10121");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);
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

if(version_in_range(version:mcaVer, test_version:"5.0.0", test_version2:"5.1.1"))
{
  report = 'Installed Version: ' + mcaVer + '\n' +
           'Fixed Version:     ' + "5.1.2" + '\n';

  security_message(data:report, port:mcaPort);
  exit(0);
}
exit(0);
